# Changelog

## 0.3.0 — 2026-10-07

- Optional Linux composite GitHub Action with SHA-pinned runtime and artifact actions.
- Trusted scanner source is loaded without installing or executing the scanned repository.
- Workspace-confined targets, hidden-file coverage and fresh private report directories.
- Privacy-reduced JSON/Markdown artifacts omit paths, snippets, fingerprints and warning text.
- Explicit findings/completeness gates run after report upload; artifact retention is bounded to seven days.
- Unit regression coverage and real runner smoke checks for the composite action.

The Action uploads reports to GitHub, unlike a standalone offline scan. Reports
retain counts, rule IDs, categories, severity, line numbers and opaque file IDs;
they are detection aids and do not establish that a repository is secret-free.
Run the CLI locally to locate findings using its more detailed private report.

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
