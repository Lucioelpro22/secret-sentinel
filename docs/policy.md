# Policy files and reviewed suppressions

Select a JSON policy explicitly with `secret-sentinel scan ROOT --policy FILE`. There is no automatic policy discovery. The historical YAML example is not loaded. Policies must be UTF-8 regular files at most 64 KiB. The selected parent path is canonicalized once, then pinned with no-follow component opens; a symlink at the policy file itself is rejected. POSIX safe-read support is required.

## Schema version 1

Top-level keys are `version` (required integer 1), `scan`, `fail_on`, and `suppressions`. Unknown or duplicate keys, malformed JSON, nonfinite values, unsupported versions and wrong types are rejected. The supported example is `.secret-sentinel.example.json`.

`scan` accepts positive integer `max_file_bytes`, `max_total_bytes`, `max_findings_per_file`, `max_line_length`; boolean `include_hidden`; and arrays of directory names `excluded_dirs` and suffixes `excluded_extensions`. Exclusions add to built-in defaults. Symlink following and detector disabling are unsupported. `fail_on` is low, medium, high or critical (default high).

Explicit CLI limits, `--include-hidden` and `--fail-on` override the corresponding policy setting. CLI exclusions add to policy and built-in exclusions. Omitting a CLI option preserves the policy value. Scope changes require review; the policy is configuration, not protection against an operator intentionally relaxing controls.

## Exact suppressions

At most 100 entries are accepted. Each entry requires:

| Field | Meaning |
|---|---|
| `rule_id` | A known detector ID, including `generic-secret-assignment` |
| `path` | Exact slash-separated path relative to a directory target; basename for a selected file |
| `fingerprint` | Exact 16 lowercase hexadecimal characters from the redacted finding |
| `reason` | Review justification, 10–500 characters after trimming |
| `expires` | Canonical YYYY-MM-DD date strictly after the current UTC date |
| `line` | Optional positive integer restricting the finding to an exact line |

No wildcard, absolute, dot-segment, backslash or control-character paths are accepted. Paths changed by metadata redaction cannot be suppressed through this mechanism. Duplicate or overlapping entries are rejected. Fingerprints are stable identifiers, not cryptographic evidence that a credential is harmless; they must not be computed from live values pasted into policies or chats.

For example, after reviewing a synthetic test fixture, copy its **reported fingerprint** into a narrow entry:

```json
{
  "version": 1,
  "suppressions": [
    {
      "rule_id": "github-token",
      "path": "tests/fixtures/synthetic.txt",
      "fingerprint": "0000000000000000",
      "line": 2,
      "reason": "Reviewed nonfunctional synthetic test fixture",
      "expires": "2026-11-01"
    }
  ]
}
```

The zero fingerprint is an illustrative placeholder, not a suppression for a real finding. Always set the actual reviewed fingerprint and a suitable future date. Do not store credentials in the reason. Known credential patterns in reasons are redacted, but unrecognized sensitive prose remains the reviewer's responsibility.

Expiry is rechecked when applying a policy, before changing findings. UTC expiration is exclusive: an entry with today's date is expired. The whole policy fails closed if any entry is invalid or expired, even if it does not match a finding. Optional line matching makes a moved finding active again; omitting line permits only the same fingerprint in the same file under the same detector.

## Reports and exit status

Matched suppressions are removed from active `findings` and retained as `suppressed_findings`, each containing the redacted finding, reason and expiration. JSON also reports `suppressed_count`; text and Markdown show a separate suppression section. This is an additive schema-v1 extension. No raw finding value is serialized.

An invalid policy exits 2 with a fixed safe diagnostic before producing a report. Incomplete input still exits 2, including when every detected finding is suppressed. Complete scans exit 1 when an active finding reaches the severity threshold and 0 otherwise. Unmatched but valid suppression entries are accepted; removing obsolete entries is part of review.

## Review lifecycle

1. Review the redacted finding and determine whether the fixture is intentionally nonfunctional.
2. Record the exact path, detector, fingerprint, reason and a short expiration.
3. Obtain code-owner review of the policy change.
4. Keep suppressed evidence in protected report artifacts.
5. Remove or renew the exception after a fresh review before expiration.

Secret Sentinel does not enforce human approval or validate credentials against their providers. It does not revoke credentials, inspect Git history or rewrite files.
