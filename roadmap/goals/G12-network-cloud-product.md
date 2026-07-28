# G12 — Network cloud product

## Outcome

Deliver the first real, sellable reference product entirely through OCS: isolated
tenant networking with subnets, addresses, routing, security policy and external
connectivity. This is the proof that the platform kernel and product standard work
without a direct service integration.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define OCS network resources: network, subnet, port/interface, address,
  security group/policy, router/gateway, route and external address attachment.
- Support IPv4 and IPv6, explicit address families, overlap validation, IPAM,
  allocation/release, quotas, capacity, meters and pricing dimensions.
- Implement a generic network connector and a reference Cilium/Gateway API
  adapter with provider bindings for BGP or L2 advertisement. Site routing stays
  downstream; lifecycle semantics stay OSS.
- Reconcile desired and actual state, discover drift, adopt explicit existing
  resources, reject unsafe implicit adoption and recover interrupted mutations.
- Enforce tenant isolation with network policy, anti-spoofing, least-privilege
  controller access and audit.
- Provide API, CLI and portal extension for topology, lifecycle, policy, status,
  cost, quota, capacity and troubleshooting.
- Implement HA, overload behavior, upgrade/rollback and diagnostics for network
  controllers; the data path must not depend on portal/API availability.

## Required journeys

- create dual-stack network/subnet, allocate addresses, attach ports, apply and
  update policy, establish external connectivity, meter and delete;
- prove allowed tenant traffic, cross-tenant denial, spoof denial and unavailable
  external route behavior;
- exhaust address/quota/capacity without leaked allocation;
- interrupt each lifecycle step, retry, reconcile drift and clean all state;
- fail the active network controller/node and preserve existing data-plane traffic;
- upgrade and roll back the product without losing allocations or policy.

## Hub and downstream delivery

Publish and install the signed reference network product from OSS. The maintained
reference deployment supplies only site address, routing and L2 bindings. Prove
direct IPv4 and IPv6 API paths, origin TLS and a bounded network failover on the
reference site. An independent downstream runs the same product conformance
against synthetic site bindings.

## Acceptance

- First real catalog/order/subscription/entitlement/meter/invoice chain succeeds.
- No network implementation is compiled into platform core.
- Current Task 23 networking defects and false-readiness paths are closed with
  live receipts tied to accepted mains.
- The product can be disabled/removed without disabling the empty provider core.
