# Security Policy

## Scope

Secret Sentinel is a local-first defensive scanner. This policy covers the scanner, its detectors, report serializers, policy parser, packaging, and CI workflows in this repository.

## Supported versions

Only the latest release on the default branch is supported during the pre-1.0 phase. Pin a release or commit in production pipelines and review changes before upgrading.

## Reporting a vulnerability

If you find a vulnerability, unsafe data-handling behavior, detector bypass with security impact, or a way to cause raw secret disclosure, do not open a public issue. Use the repository's private GitHub security advisory channel when available. If that channel is unavailable, contact the maintainer through the verified contact listed in the repository profile.

Include:

- affected version or commit;
- minimal reproduction with synthetic credentials only;
- impact and expected security boundary;
- logs or stack traces after removing sensitive values;
- a proposed mitigation, if known.

Never include a real token, password, private key, customer data, or unredacted scanner output.

## Credential exposure response

If a real credential is found during testing, assume it is compromised. Stop sharing the value, notify the owner, revoke or rotate it through the provider, then clean the repository and its history using the provider's documented process. Secret Sentinel is not a rotation service and cannot invalidate a credential for you.

## Security guarantees and limitations

The scanner aims to avoid secret exfiltration and automatic mutation. It cannot guarantee complete detection, and its reports may contain filenames, line numbers, detector names, and short redacted context. Treat reports as sensitive security metadata.

## Supply-chain expectations

Contributions should preserve pinned or bounded dependencies, reproducible tests, least-privilege CI permissions, and deterministic redaction. New detectors must include synthetic positive and negative tests and must not log matched secret material.
