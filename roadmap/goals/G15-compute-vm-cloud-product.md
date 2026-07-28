# G15 — Compute VM cloud product

## Outcome

Deliver the flagship VM product entirely through OCS, using the Network, Volume
and Image products as entitled dependencies. Customers receive a complete
self-service compute lifecycle with billing, recovery and node-loss continuity.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define VM, flavor, placement, disk, NIC, metadata, key/credential, console,
  power and migration contracts.
- Implement capacity-aware placement with reservations, anti-affinity, failure
  domains, overcommit policy and transparent reasons. Do not invent a general
  scheduler beyond measured needs.
- Implement create, start, stop, reboot, rebuild, resize, suspend, snapshot,
  migrate and delete through durable Operations.
- Use KubeVirt as the reference runtime with correct CDI/image, network and
  volume integration; keep the OCS connector portable to other compute backends.
- Provide secure console/access bootstrap, metadata protection, tenant isolation,
  resource limits and host/guest observability.
- Meter vCPU, memory, accelerator, uptime, storage and network; reserve/release
  quota and capacity transactionally.
- Implement evacuation/live migration where supported, cold recovery otherwise,
  explicit disruption contracts, backup/restore and upgrade/rollback.
- Provide complete API, CLI, portal extension, audit, support and diagnostics.

## Required journeys

- quote and create VM from verified image with network and volume; boot, access,
  meter, stop/start, resize, snapshot, restore and delete;
- reject unauthorized image/network/volume and cross-tenant console/access;
- retry after API/connector timeout without duplicate VM or billing;
- lose the hosting node and prove the declared live-migration or cold-recovery
  behavior with guest data digest and bounded disruption;
- exhaust compute capacity and fail before partial dependencies leak;
- upgrade and roll back compute product while existing VMs continue running.

## Hub and downstream delivery

Install the OSS VM product at the reference site with site-only host and capacity
bindings. Run the full journey and one bounded server-loss drill on a dedicated
test VM. An independent downstream validates KubeVirt/hardware prerequisites and
a deterministic plan using synthetic inventory.

## Acceptance

- Existing VMs do not depend on management API availability to keep running.
- Every selected image re-passes the G14 provenance/boot-compatibility contract on
  the real G15 compute path.
- Live-migration claims meet KubeVirt/storage/network prerequisites and are
  proved; unsupported cases state and prove cold-recovery behavior.
- Resource, usage, invoice and audit chains are complete and consistent.
- No VM path bypasses OCS or directly embeds site/provider logic in core.
