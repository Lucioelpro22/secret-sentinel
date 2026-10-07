# Secret Sentinel GitHub Action

The optional composite Action scans a checked-out directory as data. It uses
the scanner packaged in the reviewed Action revision, without installing the
target project or executing its scripts, build hooks or dependency managers.
Supported runners are Linux with Bash and Python 3.11 or newer; the Action sets
up Python 3.12. Self-hosted runners and earlier steps must be trusted.

## Pull request workflow

```yaml
name: Secret Sentinel
on:
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: Lucioelpro22/secret-sentinel@<reviewed-full-commit-sha>
        with:
          path: .
          fail-on: high
          fail-on-findings: "true"
          fail-on-incomplete: "true"
          include-hidden: "true"
          artifact-name: secret-sentinel-report
          retention-days: "7"
```

Replace the placeholder with the exact reviewed release commit. Use the
ordinary `pull_request` event with read-only permissions. Do not execute PR
code in a privileged `pull_request_target` job, pass credentials to this
Action, or install the target project's dependencies before scanning it.

## Inputs and outputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Existing directory relative to `GITHUB_WORKSPACE`; parent traversal, absolute paths and symlink targets are rejected. |
| `fail-on` | `high` | Severity threshold: low, medium, high or critical. |
| `fail-on-findings` | `true` | Fail the Action when an active finding meets the threshold. |
| `fail-on-incomplete` | `true` | Fail when selected input was omitted by errors or resource limits. |
| `include-hidden` | `true` | Include `.github`, `.env` and other hidden working-tree files. |
| `artifact-name` | `secret-sentinel-report` | Short validated artifact name; use a different name for each invocation in a job. |
| `retention-days` | `7` | Artifact retention from one to seven days. |

The Action produces JSON and Markdown reports in an isolated directory below
`RUNNER_TEMP`, then uploads only those two report files. Findings or an
incomplete scan still produce reports before the final failure gate. Invalid
inputs and internal failures fail without printing input values. An upload
failure also fails the Action even if findings/completeness gates are disabled.

Outputs are `finding-count`, `credential-count`, `configuration-count`,
`complete`, `scan-exit-code`, `reports-dir` and `artifact-id`. Setting both
failure gates to `false` permits reports
for review, but does not make an incomplete scan complete.

## Privacy and limitations

Reports are uploaded to **GitHub**, with access determined by the repository's
artifact permissions. Use a private repository when the retained metadata is
sensitive. The Action does not upload source files, matched secret values,
relative or absolute source paths, evidence snippets, fingerprints, policy
reasons or free-form warning text. File identifiers are opaque, local to each
report and do not identify a path. Reports retain rule IDs, severity, category,
line/column numbers and aggregate counts. They are not suitable for correlating
file identities between different scans.

To locate and remediate a finding, run the CLI locally against the same
revision and inspect its private detailed report. The Action does not load
repository policies or suppressions. Configuration findings remain static
indicators requiring human review.

Default scan budgets are 2 MB per file, 50 MB total, 100 findings per file and
20,000 characters per line. Explicit default exclusions include `.git`, `.hg`,
`.svn`, `.venv`, `node_modules` and supported binary/archive extensions.
Completeness applies only to selected working-tree text; Git history, archives,
unsupported secret formats and excluded content are outside that scope.
Concurrent edits are not a consistent snapshot. Do not run untrusted code
concurrently with scanning or artifact upload.

There is no separate file-count or directory-walk budget. Keep a job timeout
as shown above, especially for large or adversarial trees.

The runner setup and artifact upload use network services; the scanner itself
does not contact credential providers or send source code to an external API.
No deployment, revocation, rotation or automatic remediation occurs.

## References

- [GitHub: secure use of Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub: composite actions](https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action)
- [GitHub: workflow artifacts](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts)
