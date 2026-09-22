# Evidence Authoring

Evidence authoring records what a module package proves, what it does not prove,
and where a reviewer can inspect freshness and redaction. CloudRING uses
OCSv3 (Open Cloud Standard 3) evidence refs to keep service, billing, UI,
support, policy, data lifecycle, readiness, and durability claims reviewable.

## Required Surfaces

Evidence should cover:

- support diagnostics and redaction boundary;
- UI certification and integrity refs;
- policy decision evidence;
- Gateway API route evidence;
- data export and delete evidence;
- degraded and blocked state evidence;
- billing cost-meter evidence;
- readiness checks;
- recovery evidence for durable state;
- evidence bundle freshness, review path, and non-claims.

## Authoring Flow

1. Name the claim in plain language.
2. Link the evidence ref in the connector package.
3. State freshness, reviewer role, redaction boundary, and non-claims.
4. Keep artifacts synthetic or sanitized for CloudRING public.
5. Validate the package and source-safety:

```sh
go run ./cmd/ocsctl validate ./examples/synthetic-service-module/connector-package.json
go run ./cmd/ocsctl conformance ./reference/synthetic-service/module-package.json --evidence ./evidence/reference-conformance.json
```

Maintainers run source-safety before merge. Contributors should not commit
generated evidence unless it is synthetic, reviewed, and part of a public
example.

## Non-Claims

Example evidence in CloudRING does not claim production-grade readiness, a running
deployment, billing settlement, data migration, support operation, or recovery
success. It proves that the package has the metadata and evidence refs needed
for service-team, platform-operator, security-reviewer, and
enterprise/downstream maintainer review.
