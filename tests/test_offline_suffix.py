"""Regression test: the email check must never touch tldextract's disk cache.

Background (0.6.2): when the container ran as a different uid from the one that
built /app/.tldextract, Presidio's email recognizer raised PermissionError on
the cache lock file and the API returned HTTP 500 for any text with an email.

This test needs the server's Python packages (the no-Docker route):
    cd detection_api && python ../tests/test_offline_suffix.py
"""
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "detection_api"))


def main() -> int:
    # A read-only cache folder holding a lock file, like the one in the image.
    cache = Path(tempfile.mkdtemp(prefix="tldcache-"))
    lock = cache / "publicsuffix.org-tlds" / "x.tldextract.json.lock"
    lock.parent.mkdir()
    lock.touch()
    for p in (lock, lock.parent, cache):
        p.chmod(stat.S_IRUSR | stat.S_IXUSR if p.is_dir() else stat.S_IRUSR)
    os.environ["TLDEXTRACT_CACHE"] = str(cache)

    # Any lock attempt fails the test, even when run as root (root ignores chmod).
    import filelock
    import tldextract.cache as tcache

    class NoLock:
        def __init__(self, *a, **k):
            raise AssertionError(f"tldextract opened a cache lock file: {a[0] if a else ''}")

    tcache.FileLock = NoLock
    filelock.FileLock = NoLock

    from app.engine import use_offline_suffix_list
    import tldextract

    use_offline_suffix_list()
    failures = 0
    try:
        r = tldextract.extract("ravi.kumar@examplebank.co.in")
        ok = (r.domain, r.suffix) == ("examplebank", "co.in")
        print(("PASS" if ok else "FAIL"), " bundled list resolves co.in ->", r.domain, r.suffix)
        failures += not ok
    except Exception as exc:  # noqa: BLE001
        print("FAIL  extract raised", type(exc).__name__, exc)
        failures += 1

    try:
        from presidio_analyzer.predefined_recognizers import EmailRecognizer
        res = EmailRecognizer().analyze("mail ravi.kumar@examplebank.co.in today", ["EMAIL_ADDRESS"])
        ok = any(x.entity_type == "EMAIL_ADDRESS" for x in res)
        print(("PASS" if ok else "FAIL"), " Presidio email recognizer works without the cache")
        failures += not ok
    except Exception as exc:  # noqa: BLE001
        print("FAIL  email recognizer raised", type(exc).__name__, exc)
        failures += 1

    for p in (cache, lock.parent, lock):
        p.chmod(0o700)
    print(f"\n{2 - failures}/2 passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
