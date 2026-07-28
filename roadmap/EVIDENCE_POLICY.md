# Evidence resolution, freshness and retention policy

Roadmap state contains content-addressed evidence references, never raw logs or
secrets. Each reference has a SHA-256 digest, a resolver locator and a retention
deadline:

- `oci://...` identifies a sanitized, signed, immutable OCI artifact that a clean
  verifier can retrieve with public release tooling;
- `protected://<scope>/<opaque-id>` identifies protected downstream evidence. The
  configured resolver obtains it through the owning credential broker, verifies
  the digest and returns only the sanitized view allowed to that verifier.

A locator is not evidence by itself. Verification must retrieve the object,
verify its digest and attestation, validate its schema and redaction verdict, and
prove that `observedAt < expiresAt`. Goal-specific policy sets maximum freshness;
an expired or unavailable object is `unverified`, never historical success.

The semantic validator enforces rules JSON Schema cannot express:

- requirement IDs and deployment targets exactly match `roadmap.yaml` and the
  goal contract;
- every maintained reference or downstream consumer pin equals the accepted
  public SHA and all check receipts belong to those exact revisions;
- only `delivered` satisfies `dependsOn`; a goal cannot be skipped or superseded
  through a state value;
- every required target uses the same release-manifest tuple, while region and
  federation fingerprints are distinct where independence is claimed;
- measurement clocks are ordered and synchronized, thresholds are frozen before
  execution, exclusions are explicit, result artifacts reproduce the assertion,
  and the observed verdict satisfies the selected profile;
- state/index transitions are atomic and predecessor regression evidence is
  current.

Sanitized release evidence remains retrievable through the published support
lifetime plus the retention period declared by that release. Protected evidence
must remain resolvable through the later of G27 or the owning post-1.0 track's
release, terminal security review and support handoff. A goal cannot complete if
its proof would expire before the required audit or support window. Raw protected
material follows the owning provider's retention and privacy policy; only its
non-sensitive signed verdict is published.
