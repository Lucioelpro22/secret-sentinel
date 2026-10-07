# Threat Model

## Assets

- credentials accidentally stored in source, history, fixtures, or CI configuration;
- source code and repository metadata;
- scanner users' CI logs and report artifacts;
- policy integrity and the scanner's exit status.

## Adversaries

- an attacker who can submit crafted repository content;
- a malicious or compromised dependency;
- a contributor attempting to bypass a detector;
- a CI observer who can read logs or artifacts;
- an operator who configures an unsafe scope or suppression.

## Main threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Raw secret appears in output | Redaction before reporting and logging; synthetic tests | Novel encoding or an implementation defect may evade redaction |
| Path traversal or symlink escape | Pinned canonical root, no-follow component opens, bounded regular-file reads | Host-level permissions remain outside the tool's control |
| Denial of service from huge/binary input | File-size limits, bounded reads, binary detection | A very large number of files can still consume CI time |
| Detector bypass | Multiple detector families, entropy/context checks, regression corpus | Unknown formats, split values, and encrypted values may be missed |
| Unsafe remediation | Read-only architecture and no provider credentials | Operators may take unsafe manual actions after a finding |
| Policy bypass | Bounded strict JSON policies; exact fingerprint/path/rule matching; reasons, expiration and visible suppressed evidence | A user can intentionally configure a permissive policy |
| Dependency compromise | Pinned/controlled CI dependencies, audit and tests | Upstream compromise cannot be eliminated by the scanner |
| Report leakage | Redacted output and guidance to protect artifacts | Paths and metadata can still reveal sensitive project context |

## Out of scope

Secret Sentinel does not protect a compromised host, recover deleted secrets, inspect provider-side audit logs, or prove that credentials were not copied before detection.

## Security acceptance criteria

Before a release, verify that synthetic secrets are redacted in every output format, invalid scan configuration is rejected, traversal attempts stay within scope, and CI logs contain no raw match values.

Safe local scanning currently requires POSIX descriptor-relative file access (Windows users need WSL). Concurrent mutation is not a consistent snapshot. Recognized credentials and control characters in paths are sanitized; other path metadata remains sensitive.
