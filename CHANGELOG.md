# Changelog

## 0.2.0 — 2026-10-07

- Bounded descriptor-relative reads, no-follow components and regular-file checks.
- Explicit incomplete scans, configurable scope and corrected same-line detection.
- Strict JSON policies and exact reviewed expiring suppressions with visible evidence.
- Specific static debug, TLS and Django allowed-hosts indicators with categorized counts.
- Protected metadata, literal Markdown and exclusive owner-only report output.
- Synthetic regression corpus and policy-based source scanning in CI.

Safe reads require POSIX support (Windows via WSL). Working-tree text only;
Git history and archive contents are not analyzed. Static configuration findings
require human review. Unknown secrets and sensitive metadata can evade detection.
This release does not constitute external security certification.
