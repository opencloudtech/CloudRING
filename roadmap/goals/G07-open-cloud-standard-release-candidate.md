# G07 — Open Cloud Standard release-candidate developer platform

## Outcome

Publish a language-neutral OCS release candidate and a developer workflow that
lets a mid-level developer create, run, test and package an independent product
within the measured two-hour target. The contracts remain explicitly pre-1.0
until real products falsify and stabilize them.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define one canonical OCS naming/version policy and migration from current
  experimental OCSv3 packages; label unstable fields honestly.
- Specify product/package identity, operations, lifecycle, errors, IAM, tenancy,
  health, durability, observability, support, meter/quota/capacity declarations,
  API/UI surfaces and local/remote connector trust.
- Make `local`, `remote` and `api-only` execution profiles first-class. Require
  public API behavior for every product, keep signed microfrontends optional,
  and validate conditional placement contracts instead of requiring Kubernetes
  or UI metadata universally.
- Model standard lifecycle actions through `supported` or explicit
  `not_applicable` declarations with reasons; implement idempotency, durable
  operations and recovery boundaries for every supported mutation.
- Model explicit `metered`, `zero-priced-metered` and `non-billable` policies,
  provider-controlled audiences/regions, and product dependencies carrying
  infrastructure-user entitlement, region, quota/capacity and billing
  attribution.
- Use pinned OpenAPI, CloudEvents and AsyncAPI profiles and signed OCI packages
  with SBOM, provenance and licence metadata.
- Publish strict schemas rejecting unknown fields, invalid enums, duplicates,
  ambiguous references and incompatible versions.
- Provide public Go SDK, generated language-neutral clients, test server,
  connector helpers, compatibility kit and `cloudring service
  init|dev|validate|test|package`.
- Provide an ephemeral conformance runner and tutorial connector in test/sandbox
  only. Persistent registry/activation belongs to G08.
- Require a service built in an empty independently controlled repository/CI
  using only released public artifacts, with no non-public checkout or author
  cache.

## Required journeys

- implement original domain behavior from an empty repository and pass positive/
  negative conformance within the DX measurement rules;
- reproduce a signed package, reject tampering and verify SBOM/provenance;
- connect locally/remotely, interrupt/reconnect idempotently and rotate identity;
- validate an API-only remote product with no Kubernetes binding and no portal
  module, and a local product without a portal module;
- upgrade across a declared compatible candidate and reject incompatibility;
- generate clients/docs reproducibly from source schemas;
- run the tutorial and an independently built package through the ephemeral runner,
  then remove all test state.

## Hub and downstream delivery

Run only the ephemeral conformance environment in isolated hub scope. Publish SDK
and package artifacts from public `main`. Both downstreams remove duplicated OCS
types/validators for the touched surface and use the public candidate unchanged.

## Acceptance

- Issues #87, #88 and #95 close with strict runtime-consumer regression suites.
- Every schema has a validator and consumer or is removed.
- The independently built package proves no private or unpublished dependency.
- No “OCS 1.0” or accredited-standard claim is made before G27.
- `validate` and `conformance` use one canonical public validator and return the
  same schema verdict for every positive and negative fixture.
