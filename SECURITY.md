# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's **"Report a vulnerability"** button (Security tab → Advisories) rather than in a public issue. Include the version (`VERSION`), what you found, and steps to reproduce, with synthetic data only.

## Scope and expectations

This project is a reference implementation of a data-protection control for AI coding assistants. Before relying on it, read its documented limits:
- [docs/ide-hooks.md](docs/ide-hooks.md): what the hooks can and can't intercept.
- [docs/intune.md, section 9](docs/intune.md#9-limits): fleet limits.

Notable by design:
- **Client-side enforcement.** A user with local administrator rights can remove it; fleet deployments must remove local admin rights.
- **Detection is probabilistic.** Pattern and language-model detection has false negatives and false positives; tune `policy.yaml` and `rules/recognizers.json` for your data and test with your own synthetic samples.
- **Never store real customer data, tokens or keys** in rules test samples, policy files or issues. Every sample in this repository is synthetic.

It is not legal or compliance advice. Mapping it to RBI, DPDP, PCI DSS or internal requirements is the deploying organization's responsibility.
