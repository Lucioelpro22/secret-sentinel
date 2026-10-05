# Secret Sentinel

Secret Sentinel is a defensive, local-first scanner for detecting accidentally committed credentials and unsafe configuration in source trees and CI artifacts.

It is designed for engineers and security teams that need a repeatable pre-commit or CI control without sending source code to a third party. Findings are normalized, classified, and redacted before they are rendered in reports.

> **Status:** early baseline / pre-1.0. Use it as a detection aid, not as proof that a repository is secret-free.

## What it does

- Scans files and selected repository metadata with explicit scope boundaries.
- Detects high-confidence credential patterns and unsafe configuration indicators.
- Applies entropy and context checks to reduce noisy matches.
- Redacts secret material in console, JSON, and Markdown output.
- Assigns severity, confidence, detector ID, and remediation guidance.
- Supports deterministic output for CI review and regression tests.
- Fails closed on unreadable input, malformed policy, or unsafe configuration.

## What it does not do

- It does not validate credentials against a service.
- It does not transmit source code, findings, or secret values to an external API.
- It does not rotate, revoke, delete, or rewrite credentials.
- It does not push commits, open pull requests, or alter repository settings.
- It does not guarantee the absence of secrets; encoded, split, encrypted, or novel formats may evade detection.

## Quick start

The current baseline exposes an offline, read-only Python API:

```python
import json
from secret_sentinel import ScanConfig, Scanner

report = Scanner(ScanConfig()).scan(".")
print(json.dumps(report.to_dict(), indent=2))
```

Install the package and run the CLI against an explicit file or directory:

```bash
python -m pip install .
secret-sentinel scan . --format json --output secret-report.json --fail-on high
```

Pin the package revision in CI. API integrations must check `report.complete` as well as findings; an incomplete scan cannot establish a clean result.

## Safe operating model

1. Run locally before publishing or sharing a branch.
2. Review findings in the redacted report only.
3. Treat every high-confidence finding as potentially live.
4. Revoke and replace exposed credentials through the owning provider.
5. Remove the credential from history using an approved repository procedure.
6. Re-run the scanner and preserve the report as audit evidence.

Do not paste raw findings into tickets, chat, issue comments, or logs. The scanner intentionally does not print secret values.

## CI contract

The redacted `ScanReport.to_dict()` schema includes an additive `complete` boolean and `warnings`. Text and Markdown reports also show scan completeness and warnings.

| Exit code | Meaning |
| --- | --- |
| `0` | All selected input was scanned; no finding met `--fail-on` |
| `1` | Complete scan with a finding at or above `--fail-on` |
| `2` | Missing/unreadable target, unreadable selected input, or resource truncation; findings may still be present |

Incomplete scans take precedence over the severity threshold. File/total-byte limits, line-length truncation, and omitted text after a per-file finding cap produce an incomplete report. Finding caps apply independently to each file; reaching a cap in one file never stops scanning other files. Explicit exclusions, hidden files excluded by policy, binary files, and empty files do not make a scan incomplete. Completeness describes coverage of the configured scope, not proof that every possible secret format was detected.

## Development

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy src
```

See [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), and [docs/safe-use.md](docs/safe-use.md) before enabling the scanner in a production pipeline.

## Security reporting

Please do not disclose credentials or exploit details in a public issue. Follow [SECURITY.md](SECURITY.md).

## License

See [LICENSE](LICENSE). The project is intended for authorized defensive use only.
