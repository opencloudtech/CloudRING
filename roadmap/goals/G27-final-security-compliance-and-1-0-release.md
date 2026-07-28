# G27 — Final security, compliance and CloudRING 1.0 release

## Outcome

After all functionality exists, perform the broad adversarial review, fix every
release blocker and publish the standalone platform plus OCS 1.0 as a
reproducible, supportable release for independent providers. Multi-region and
federation remain explicit post-1.0 tracks and are not release dependencies.

All reusable fixes must merge into public OSS and the final accepted release must
be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Freeze features and audit every G00-G24 requirement, issue-map row,
  `LEGACY_WORK_MAP.md` obligation and capability-matrix cell. No required item may
  be silently moved outside 1.0.
- Threat-model provider, tenant, product, browser, agent, supply chain, operator,
  connector, federation-ready schema boundaries, billing, backup and recovery.
- Run deep code/security, SAST, dependency/vulnerability, secret/source-safety,
  fuzz/race, RBAC, network, container, IaC, provenance, licence and boundary audits.
- Test real-runtime authentication, authorization, isolation, confused deputy,
  SSRF, injection, replay, CSRF, session, break-glass and package sandbox
  negatives. Verify that disabled federation surfaces cannot create an exposure
  or standalone dependency; live federation security belongs to G26's later
  release gate.
- Audit GDPR/data-residency engineering controls, retention/deletion, access
  review, audit integrity, incident response and DPA-ready documentation without
  claiming legal certification not granted by an authority.
- Fix release-blocking findings in OSS first, propagate pins, redeploy all
  providers and rerun affected and cumulative gates. Risk acceptance cannot waive
  a critical/high exploitable issue, secret/public-boundary breach, tenant escape,
  data-loss path or broken release provenance.
- Freeze OCS 1.0 from the release candidate only after real Network, Volume,
  Image, VM and one remote/API-only product plus two provider implementations
  pass positive, negative, lifecycle and upgrade compatibility. The standard's
  mandatory API, optional microfrontend and local/remote/API-only profiles must
  share one canonical validator.
- Publish docs, compatibility/support matrix, migrations, threat model, runbooks,
  SDKs, conformance, images/packages, SBOM, provenance, signatures and source tag.

## Required final proof

- clean-clone empty provider and every reference product through OCS;
- complete human/API/CLI/scoped-agent parity and audit;
- one-server-loss, database/storage/network/secret failover, off-cell restore and
  zero-downtime signed N-1-to-N upgrade;
- continuous platform API, portal, ID, IAM, usage ingest, rating, ledger and
  invoice-read correctness through replica loss and the signed upgrade;
- the maintained reference deployment reproducibly serves its public endpoint
  from the exact final pin;
- an independently controlled clean-room site installs, operates, backs up and
  restores, upgrades, rolls back and removes the provider plane and one
  independently owned OCS product using only released public artifacts and its
  own infrastructure;
- all exact CI/protection/SafePush checks green; no required open issue,
  unclassified WIP, duplicate, placeholder, private dependency or hidden step.

## Release acceptance

- Ledger contains no required blocked/unverified item. The only architectural
  expansion tracks outside 1.0 are G25 multi-region and G26 opt-in federation;
  they cannot satisfy or waive a standalone release requirement.
- Capability matrix proves every applicable runtime, data, IAM, UX, billing,
  observability, HA, backup, upgrade, test, docs and live cell.
- Measurement objectives pass with immutable candidate artifacts.
- A real signed tag, SBOM and provenance verify from a fresh environment.
- Final public, maintained-reference and independent-downstream revisions, pins,
  GitOps revisions, artifacts, cleanup and support handoff are recorded without
  secrets.

## Completion statement

Only after findings are fixed and every final proof passes may CloudRING 1.0 be
released for production use by independent providers. Green CI, a live hub or a demo
alone is insufficient.
