# Architecture

Secret Sentinel separates collection, detection, policy, and presentation so that a finding can be tested without coupling it to a filesystem or CI platform.

```mermaid
flowchart LR
  A[Scoped input] --> B[Safe collector]
  B --> C[Detectors]
  C --> D[Normalizer]
  D --> E[Policy gate]
  E --> F[Redacted reports]
```

## Components

### Scoped collector

The collector accepts an explicit root and applies include/exclude rules, file-size limits, symlink policy, and binary-file handling. It must never follow an unbounded path or read outside the requested scope.

### Detector registry

Detectors are small, deterministic functions. Each finding carries a detector ID, match location, confidence, severity, description and redacted evidence. Detector implementations receive bounded text and must not emit the matched value. Configuration detectors inspect supported line syntax and Python AST without executing code, returning canonical evidence and category `configuration`; credential detectors remain separate.

### Normalizer and redactor

The normalizer deduplicates overlapping matches and produces a stable finding schema. Redaction happens before serialization, logging, test failure output, or exception rendering. Raw match values are not part of the public domain model.

### Policy gate

The gate validates explicitly selected versioned JSON policy files using bounded no-follow reads. It applies exact, reviewed, expiring suppressions and maps remaining findings to an exit status. Suppressed evidence stays visible in the report and cannot change incomplete coverage to complete.

`ScanReport.complete` records whether selected input was fully processed. Read/traversal failures and resource truncation set it to false and append a safe warning. CLI policy gives incomplete input exit `2` before considering finding severity. Each file has its own finding budget, so truncating one file cannot consume another file's budget.

### Reporters

JSON is for automation; Markdown is for human review. Both use the same redacted finding model so they cannot diverge on secret handling.

## Trust boundaries

The repository being scanned is untrusted input. File names, encodings, symlinks, archive members, and detector input can be adversarial. CI logs and report artifacts are also treated as sensitive outputs.

## Design invariants

- no network access is required for a scan;
- no provider validation or credential use;
- no repository mutation;
- deterministic findings for identical input, policy, and version;
- matched secret values are redacted before reporting; recognized credential patterns in paths are sanitized, while other metadata remains sensitive.
