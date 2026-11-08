"""Presidio engine setup, scanning, redaction and file text extraction."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
from collections import OrderedDict
from dataclasses import dataclass

import threading

import regex
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    InAadhaarRecognizer,
    InGstinRecognizer,
    InPanRecognizer,
    InPassportRecognizer,
    InVehicleRegistrationRecognizer,
    InVoterRecognizer,
)

from . import policy as pol
from . import rules as rl

from .settings import Settings

TEXT_EXT = {
    ".txt", ".md", ".csv", ".tsv", ".json", ".yaml", ".yml", ".xml", ".html", ".htm",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rs", ".rb", ".php",
    ".cs", ".c", ".h", ".cpp", ".hpp", ".sql", ".sh", ".ps1", ".bat", ".ini", ".cfg",
    ".conf", ".toml", ".properties", ".env", ".log", ".ipynb", ".tf", ".gradle",
}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp"}


def use_offline_suffix_list() -> None:
    """Make Presidio's email and URL checks use the bundled Public Suffix List.

    Presidio validates email domains with tldextract. Its default extractor keeps a
    disk cache guarded by a lock file, and may download the list on first use:
    - If the cache folder isn't writable by the user the container runs as (the
      image built it as uid 10001, compose runs it as your uid), opening the lock
      file raises PermissionError and every scan containing an email returns
      HTTP 500. The hook then fails closed.
    - In a container without internet access the download can stall.
    cache_dir=None disables the cache, so no lock file is ever opened, and
    suffix_list_urls=() uses the snapshot shipped inside tldextract.
    """
    import tldextract.tldextract as tld

    tld.TLD_EXTRACTOR = tld.TLDExtract(suffix_list_urls=(), cache_dir=None)


def value_hash(key: bytes, value: str) -> str:
    """Keyed hash of a matched value: lets the SIEM correlate repeats without storing it."""
    return hmac.new(key, value.encode("utf-8", "ignore"), hashlib.sha256).hexdigest()[:16]


@dataclass
class Finding:
    entity: str
    score: float
    start: int
    end: int
    action: str
    policy_source: str
    value_hash: str
    recognizer: str
    pattern: str = ""
    rules_version: str = ""


WARMUP_TEXT = ("Contact Priya Sharma at priya.k@example.co.in or +91 98765 43210, PAN ABCPE1234F, "
               "https://example.com, IFSC HDFC0001234")


def build_custom_recognizers(ruleset: rl.RuleSet) -> list[PatternRecognizer]:
    """Presidio recognizers for the enabled entries of a validated rules file."""
    return [
        PatternRecognizer(
            supported_entity=spec.entity,
            name=spec.name,
            supported_language=ruleset.language,
            patterns=[Pattern(p.name, p.regex, p.score) for p in spec.patterns],
            context=list(spec.context) or None,
            global_regex_flags=rl.flag_value(spec.flags, regex),
            version=ruleset.version,
        )
        for spec in ruleset.enabled
    ]


class Engine:
    """Presidio analyzer built from Presidio's recognizers plus the rules file.

    apply_rules() builds a complete new analyzer for a new rules version, warms
    it up, and only then swaps it in. Requests already running finish on the
    old analyzer; no request ever sees a half-built one.
    """

    def __init__(self, settings: Settings, ruleset: rl.RuleSet):
        self.settings = settings
        use_offline_suffix_list()
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": settings.nlp_model}],
            }
        )
        self.nlp_engine = provider.create_engine()
        registry = RecognizerRegistry(supported_languages=["en"])
        registry.load_predefined_recognizers(nlp_engine=self.nlp_engine, languages=["en"])
        loaded = {r.name for r in registry.recognizers}
        for cls in (
            InAadhaarRecognizer, InPanRecognizer, InVoterRecognizer,
            InPassportRecognizer, InGstinRecognizer, InVehicleRegistrationRecognizer,
        ):
            rec = cls()
            if rec.name not in loaded:
                registry.add_recognizer(rec)
        # Presidio's own recognizers (with their checksum validators) stay in code.
        self._base = list(registry.recognizers)
        self.builtin_names = {r.name for r in self._base}
        self._cache_size = settings.cache_size
        self._image_analyzer = None
        self._swap_lock = threading.Lock()
        self._state: tuple = ()
        self.apply_rules(ruleset)

    def apply_rules(self, ruleset: rl.RuleSet) -> None:
        """Build, warm up and swap in an analyzer for this rules version.
        Raises RulesError (and leaves the current analyzer in force) on failure."""
        clash = sorted(self.builtin_names & {r.name for r in ruleset.enabled})
        if clash:
            raise rl.RulesError([f"recognizer name(s) already used by Presidio: {', '.join(clash)}"])
        try:
            custom = build_custom_recognizers(ruleset)
            registry = RecognizerRegistry(recognizers=self._base + custom, supported_languages=["en"])
            analyzer = AnalyzerEngine(registry=registry, nlp_engine=self.nlp_engine,
                                      supported_languages=["en"])
            # Warm up every recognizer once (NLP pipeline, email/URL validation, India
            # IDs, the new patterns) so the first real request is as fast as later
            # ones. At start-up /healthz answers only after this.
            analyzer.analyze(text=WARMUP_TEXT, language="en")
            entities = sorted(analyzer.get_supported_entities(language="en"))
        except rl.RulesError:
            raise
        except Exception as exc:  # noqa: BLE001 - anything Presidio raises
            raise rl.RulesError([f"Presidio could not build the recognizers: {exc}"]) from exc
        with self._swap_lock:
            # One tuple, replaced in a single assignment: a request reads analyzer,
            # cache, entities and version from the same rules version.
            self._state = (analyzer, OrderedDict(), entities, ruleset.version)
            self._image_analyzer = None

    @property
    def analyzer(self) -> AnalyzerEngine:
        return self._state[0]

    @property
    def supported_entities(self) -> list[str]:
        return self._state[2]

    @property
    def rules_version(self) -> str:
        return self._state[3]

    # ------------------------------------------------------------------ text
    def _raw_results(self, text: str, entities: list[str], state: tuple):
        analyzer, cache = state[0], state[1]
        key = hashlib.sha256(("|".join(entities) + "\x00" + text).encode("utf-8", "ignore")).hexdigest()
        if key in cache:
            cache.move_to_end(key)
            return cache[key]
        results = []
        size = self.settings.chunk_chars
        for offset in range(0, len(text), size):
            chunk = text[offset : offset + size]
            # return_decision_process keeps the matching pattern's name for the audit log.
            for r in analyzer.analyze(text=chunk, language="en", entities=entities,
                                      return_decision_process=True):
                r.start += offset
                r.end += offset
                results.append(r)
        cache[key] = results
        if len(cache) > self._cache_size:
            cache.popitem(last=False)
        return results

    def scan_text(self, text: str, policy: pol.Policy, channel: str, user: str) -> list[Finding]:
        text = text[: self.settings.max_text_chars]
        state = self._state
        entities = [e for e in state[2] if e not in policy.disabled_entities]
        findings: list[Finding] = []
        for r in self._raw_results(text, entities, state):
            resolved = pol.resolve(policy, r.entity_type, r.score, channel, user)
            if resolved is None:
                continue
            action, source = resolved
            findings.append(
                Finding(
                    entity=r.entity_type,
                    score=round(float(r.score), 3),
                    start=r.start,
                    end=r.end,
                    action=action,
                    policy_source=source,
                    value_hash=value_hash(self.settings.hash_key, text[r.start : r.end]),
                    recognizer=(r.recognition_metadata or {}).get("recognizer_name", ""),
                    pattern=getattr(r.analysis_explanation, "pattern_name", None) or "",
                    rules_version=state[3],
                )
            )
        return _drop_overlaps(findings)

    @staticmethod
    def redact(text: str, findings: list[Finding]) -> str:
        """Replace every finding whose action is mask, pseudonymize or block."""
        out, cursor = [], 0
        for f in sorted(findings, key=lambda f: f.start):
            if f.action not in ("mask", "pseudonymize", "block") or f.start < cursor:
                continue
            out.append(text[cursor : f.start])
            if f.action == "pseudonymize":
                out.append(f"<{f.entity}:{f.value_hash[:8]}>")
            else:
                out.append(f"<{f.entity}>")
            cursor = f.end
        out.append(text[cursor:])
        return "".join(out)

    # ----------------------------------------------------------------- images
    def _image_engine(self):
        if self._image_analyzer is None:
            from presidio_image_redactor import ImageAnalyzerEngine

            self._image_analyzer = ImageAnalyzerEngine(analyzer_engine=self.analyzer)
        return self._image_analyzer

    def scan_image(self, data: bytes, policy: pol.Policy, channel: str, user: str):
        """OCR an image. Returns (findings, redacted_png_bytes or None)."""
        from PIL import Image
        from presidio_image_redactor import ImageRedactorEngine

        image = Image.open(io.BytesIO(data))
        image.load()
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")
        entities = [e for e in self.supported_entities if e not in policy.disabled_entities]
        results = self._image_engine().analyze(image, entities=entities, language="en")
        findings = []
        for r in results:
            resolved = pol.resolve(policy, r.entity_type, r.score, channel, user)
            if resolved is None:
                continue
            action, source = resolved
            findings.append(
                Finding(r.entity_type, round(float(r.score), 3), 0, 0, action, source,
                        value_hash=f"img:{r.left},{r.top},{r.width},{r.height}",
                        recognizer="ImageAnalyzerEngine", rules_version=self.rules_version)
            )
        redacted = None
        to_hide = sorted({f.entity for f in findings if f.action in ("mask", "pseudonymize", "block")})
        if to_hide:
            redactor = ImageRedactorEngine(image_analyzer_engine=self._image_engine())
            out = redactor.redact(image, fill=(0, 0, 0), entities=to_hide, language="en")
            buf = io.BytesIO()
            out.save(buf, format="PNG")
            redacted = buf.getvalue()
        return findings, redacted

    # ------------------------------------------------------------------ files
    def extract_text(self, filename: str, data: bytes) -> tuple[str | None, str]:
        """Return (text, method). text is None when the file cannot be scanned."""
        ext = os.path.splitext(filename.lower())[1]
        if ext == ".pdf" or data[:5] == b"%PDF-":
            return self._pdf_text(data)
        if ext in TEXT_EXT or b"\x00" not in data[:8192]:
            try:
                return data.decode("utf-8"), "utf-8"
            except UnicodeDecodeError:
                return data.decode("latin-1"), "latin-1"
        return None, "binary-unscanned"

    def _pdf_text(self, data: bytes) -> tuple[str | None, str]:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        if text.strip():
            return text, "pdf-text"
        # Scanned PDF: render pages and OCR them.
        try:
            import pypdfium2 as pdfium
            import pytesseract

            pdf = pdfium.PdfDocument(data)
            pages = []
            for i in range(min(len(pdf), self.settings.max_pdf_ocr_pages)):
                pil = pdf[i].render(scale=2).to_pil()
                pages.append(pytesseract.image_to_string(pil))
            return "\n".join(pages), "pdf-ocr"
        except Exception:  # noqa: BLE001 - any OCR failure means "could not scan"
            return None, "pdf-unscanned"


def _drop_overlaps(findings: list[Finding]) -> list[Finding]:
    """Where findings overlap, keep the most severe, then highest-score, then longest."""
    ranked = sorted(
        findings,
        key=lambda f: (pol.SEVERITY[f.action], f.score, f.end - f.start),
        reverse=True,
    )
    kept: list[Finding] = []
    for f in ranked:
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


def b64decode(s: str) -> bytes:
    return base64.b64decode(s, validate=False)
