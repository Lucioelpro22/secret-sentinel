# Safe Use Guide

## Before scanning

- Run with the least filesystem permissions needed.
- Define an explicit scan root and exclusions.
- Avoid scanning live credential stores, home directories, mounted cloud metadata, or production hosts.
- Use synthetic values in tests and examples.
- Treat the output directory and CI artifacts as sensitive.

## In CI

Use a pinned version, a read-only checkout, minimal token permissions, and an explicit failure threshold. Do not pass provider credentials to the scanner. Upload only the redacted report, and set an appropriate retention period.

Example integration wrapper (until the CLI milestone is released):

```yaml
- name: Scan for exposed secrets
  run: python scripts/run_secret_sentinel.py
```

Do not print the report with `cat` into logs. Review it as an artifact with access controls.

## When a finding appears

1. Assume the value is compromised, even if it looks like a test token.
2. Identify the owning system without copying the value into a ticket.
3. Revoke or rotate it using the provider's supported process.
4. Remove it from the working tree and, where necessary, rewrite history.
5. Add a safe regression fixture or detector suppression only when justified.
6. Re-run the scanner and record the remediation without the secret.

Secret Sentinel does not perform steps 3 or 4 automatically by design.

## Suppressions

Prefer removing the false positive. If suppression is necessary, scope it to a detector and exact file or line, record the reason and expiry, and require code-owner review. Never suppress a broad pattern merely to make CI green.

## Limitations

No scanner catches every secret. Review generated files, Git history, build logs, package manifests, infrastructure configuration, and external systems according to your organization's incident-response policy.
