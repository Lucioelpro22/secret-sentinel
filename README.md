# Secret Sentinel

Secret Sentinel is a defensive, local-first scanner for detecting accidentally committed credentials in source trees and CI artifacts.

It is designed for engineers and security teams that need a repeatable pre-commit or CI control without sending source code to a third party. Findings are normalized, classified, and redacted before they are rendered in reports.

> **Status:** early baseline / pre-1.0. Use it as a detection aid, not as proof that a repository is secret-free.

## What it does

- Scans selected working-tree files with explicit scope boundaries.
- Detects common credential patterns, high-entropy quoted assignments and specific unsafe configuration literals.
- Applies entropy and context checks to reduce noisy matches.
- Redacts secret material in console, JSON, and Markdown output.
- Assigns severity, confidence, detector ID, and redacted evidence.
- Supports deterministic output for CI review and regression tests.
- Marks unreadable or truncated input incomplete and rejects invalid scan configuration.

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
secret-sentinel scan . --include-hidden --format json --output secret-report.json --fail-on high
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

## Scope and platform support

Use `--include-hidden` to scan `.env` and `.github`; hidden files are omitted by default. Add directory-name exclusions with repeatable `--exclude-dir dist` and suffix exclusions with `--exclude-extension .log`. These add to defaults. Set positive `--max-file-bytes` and `--max-total-bytes` to bound reads. An explicitly selected file is scanned even when its name matches a directory-scan exclusion.

Safe reads require POSIX directory descriptors and no-follow support; use WSL on Windows. Unsupported platforms produce incomplete scans (exit 2). A selected target symlink resolves once to the selected canonical target; symlinks inside that target are excluded, and `follow_symlinks=True` is rejected. The root is pinned while files are read, but concurrent edits are not a consistent filesystem snapshot.

`bytes_scanned` counts bytes consumed, including skipped binary input and bounded overflow probes, capped at the total budget; overflow may read one additional sentinel byte. Binary files remain excluded from detector analysis. Reports hide recognized credential patterns and escape control characters in paths; paths can still contain sensitive or unrecognized values.

Versioned JSON policies and exact expiring suppressions are supported through an explicit `--policy` option; see [docs/policy.md](docs/policy.md). YAML policy loading, archive contents and Git history scanning are not implemented.

Report output uses exclusive creation with owner-only permissions. An existing output file or symlink is rejected (exit 2) to prevent source-file overwrite; choose a new report path on each run. Markdown path metadata is rendered as literal text.

## Reviewed policy

```bash
secret-sentinel scan . --policy .secret-sentinel.example.json --format json --output new-secret-report.json
```

Policies are validated before scanning and are never discovered automatically. Unknown keys, duplicate JSON keys, invalid values and expired suppressions fail with exit 2. Suppressed findings remain visible under `suppressed_findings` and `suppressed_count`; `findings` and `secret_count` represent active findings. Incomplete coverage always retains exit 2.

## Unsafe configuration checks

The scanner also reports specific debug, TLS-verification and Django allowed-hosts patterns with `category: configuration`. See [docs/unsafe-configuration.md](docs/unsafe-configuration.md) for exact syntax, severity and limitations. These are review indicators, not proof of runtime exposure. Active findings expose `finding_count`, `credential_count` and `configuration_count`; the legacy `secret_count` key/property remains a total of active findings for compatibility. Suppressed findings remain visible separately.
