# Roadmap

The roadmap is directional; security and correctness take priority over feature breadth.

## v0.1 — baseline

- deterministic local scan;
- redacted JSON and Markdown reports;
- explicit scope and policy configuration;
- common token, private-key, password, and unsafe-configuration detectors;
- unit tests for positive, negative, redaction, traversal, and malformed-policy cases;
- CI quality gates and dependency auditing.

## v0.2 — engineering hardening

- detector corpus with synthetic fixtures;
- archive and generated-file handling with strict resource limits;
- SARIF output without secret material;
- documented suppression lifecycle;
- benchmark suite for large repositories;
- reproducible release artifacts and provenance.

## v0.3 — workflow integration

- pre-commit integration;
- reusable GitHub Actions workflow with least-privilege permissions;
- baseline mode for existing repositories, with explicit review and expiry;
- signed reports and stable schema versioning.

## Future / not automatic by default

Provider-specific rotation suggestions, history analysis, and pull-request annotations may be explored only with explicit user configuration, strict redaction, and human approval. Automatic revocation, deletion, rewriting, or repository mutation is outside the default safety boundary.
