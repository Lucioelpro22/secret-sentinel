# Unsafe configuration indicators

These offline static checks supplement credential detection. They do not execute configuration, resolve dependencies, contact services or establish that a setting reaches production. All three rules have medium confidence because context and runtime behavior require human review.

| Detector ID | Severity | Recognized indicators |
|---|---|---|
| `config-debug-enabled` | medium | `DEBUG`, `FLASK_DEBUG`, `DJANGO_DEBUG` enabled; Python `app.run(debug=True)` |
| `config-tls-verification-disabled` | high | Environment `NODE_TLS_REJECT_UNAUTHORIZED=0`, `PYTHONHTTPSVERIFY=0`; literal Python `requests.METHOD(..., verify=False)` or `ssl._create_unverified_context()` |
| `config-wildcard-allowed-hosts` | medium | Literal Python list/tuple `ALLOWED_HOSTS` containing `"*"` |

Recognized Python request method names are `get`, `post`, `put`, `patch`, `delete`, `head`, `options` and `request`. The receiver must literally be `requests`. The debugger call receiver must literally be `app`; TLS context receiver must literally be `ssl`. Aliases, custom clients, import provenance, shadowed names, variables and runtime branches are not resolved. Disabled/safe literal counterparts do not produce these findings.

## Files and syntax

Python `.py` files are inspected as bounded individual lines with AST parsing. Comments and string expressions do not match. Multiline string spans are skipped by configuration detection; credential detection still checks their text. Multiline calls, lists and continuations are not interpreted. If Python tokenization fails, configuration checks may omit malformed regions or the entire file; credential checks still run. An assignment in an inactive branch or function can still be reported as a review indicator.

Environment `.env`, `.env.*` variants and files ending `.env`, `.ini`, `.cfg`, `.toml`, `.yaml`, `.yml` or `.json` use narrow standalone key/value syntax, not a full configuration parser. Keys must match their documented uppercase names. Recognized enabled debug values are true/1, optionally quoted; TLS environment switches require 0. Separator rules depend on the extension. Comments starting with `#` or `;` are excluded; supported trailing comments do not become evidence. Markdown, text documentation, shell scripts and other extensions do not run configuration checks. Secret detection continues across selected text files independently.

JSON supports a single recognized key/value pair on a line, optionally enclosed in braces or ending with a comma. Other formats inspect standalone assignments. Nested section semantics, interpolation, multiline strings/blocks and precedence between files are not evaluated; review findings in their file context. An arbitrary same-named custom setting may not have the inferred framework effect. Native filesystem permissions, CORS, network reachability and authorization settings are not assessed by this block.

Hidden files such as `.env` are still outside default scope: use `--include-hidden` or the JSON policy example. Files skipped by existing scope and binary policy remain skipped. Configuration line checks also have a hard 20,000-character parsing ceiling. All configuration matches share the existing finding, line and byte limits; truncation still produces incomplete coverage (exit 2). Unknown syntax may evade these detectors even in a complete scan.

## Evidence and policy

Configuration evidence is static canonical text such as `DEBUG=true` or `requests.verify=false`. It never includes the source line, URL, hostname, password or other call arguments. Line and column point to the recognized syntax. Its fingerprint identifies that canonical setting, so adjacent arguments or whitespace do not change it. Repeated identical indicators in the same line and rule are deduplicated consistently with the existing scanner contract.

Findings carry `category: configuration`; existing credential findings carry `category: secret`. JSON provides `finding_count` (all active findings), `credential_count` and `configuration_count`. The legacy `secret_count` remains an active-finding total for backwards compatibility. Text and Markdown display the category. The same severity threshold applies to both kinds of finding; default `--fail-on high` fails for TLS indicators but medium debug/host indicators require a lower threshold to fail.

A development-only exception can use the existing exact rule/path/fingerprint suppression, with a reason, future UTC expiry and optional exact line. Suppressed evidence stays visible. Do not blanket-suppress a detector to make CI pass.

## Review and remediation

- Debug: review the deployment environment; disable framework debugging and interactive diagnostics in production.
- TLS: restore certificate verification and configure a trusted CA bundle instead of turning verification off.
- Django host wildcard: review reverse-proxy/host validation and configure an explicit allowed-host list appropriate to deployment.

These are review suggestions. Secret Sentinel does not modify source files, validate credentials or enforce deployment policy.
