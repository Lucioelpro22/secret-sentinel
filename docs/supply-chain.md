# Supply-chain and release controls

Secret Sentinel is distributed as a source repository and (optionally) a Python
package. Release automation is deliberately narrow: it builds from an
immutable tag, records hashes, and produces provenance attestations. It does
not publish to PyPI or change repository settings automatically.

## Required release controls

1. Protect `main` and require the CI and CodeQL checks before merging.
2. Require two-person review for workflow, packaging, and dependency changes.
3. Create annotated tags matching the version in `pyproject.toml` (for example,
   `v0.1.0`) only after the tagged commit has passed CI.
4. Keep GitHub Actions pinned or centrally controlled. Dependabot updates the
   action references and Python development dependencies.
5. Review the generated artifact hashes and provenance attestation before
   distributing an artifact.

The release workflow has no long-lived registry token. If PyPI distribution is
introduced later, use PyPI trusted publishing with a dedicated environment,
required reviewers, and `id-token: write`; never add a username/password or an
API token to repository secrets.

## Artifact evidence

For each release, retain the wheel, source distribution, SHA-256 manifest, and
the dependency inventory produced by the supply-chain workflow. The inventory
is a build input record, not a declaration that transitive packages are safe;
the dependency audit and human review remain required.

## Incident response

If a release or dependency is suspected to be compromised, stop distribution,
revoke the affected release/tag, open a security report using `SECURITY.md`,
and publish a replacement release with a new tag. Never “repair” a published
artifact in place.
