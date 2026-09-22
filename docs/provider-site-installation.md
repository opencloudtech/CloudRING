# Provider Site Preflight And Plan

CloudRING defines a provider-neutral site profile so downstream providers can
describe inventory and installation dependencies without forking platform
code. The profile contains references to provider-owned inventory, network,
storage, identity, GitOps, observability, upgrade, and rollback records. It
must not contain credentials, tenant data, or live endpoint values.

Validate a profile and render its deterministic plan:

```sh
go run ./cmd/cloudring-site preflight --profile ./examples/provider-site-profile.yaml
go run ./cmd/cloudring-site plan --profile ./examples/provider-site-profile.yaml
```

Preflight fails closed unless the profile declares at least three control-plane
nodes, three workers, and three public Gateway nodes, with every role spread
across at least three failure domains;
unique provider-resource, management-address, and provisioning-address
references; dual-stack networking;
one health-checked dual-stack control-plane API endpoint which is not any
node's management or provisioning address, is covered by the API serving
certificate, and is also the exact bootstrap endpoint used by the CNI network
agent or another pre-Service API client;
stable IPv4 and IPv6 public-ingress addresses backed by an L2 VIP, BGP VIP,
provider load balancer, or anycast implementation, plus provider-owned health
check and failover-policy references (DNS round robin over node addresses is
not an HA implementation);
at least 1024 inotify instances per host, with provider-owned persistence and
post-bootstrap verification references;
snapshot-capable storage; immutable off-cell backup; OIDC, workload identity,
and a provider-owned runtime-input broker backed by its secret store; GitOps
bootstrap, upgrade, and rollback inputs; metrics,
logs, traces, and alerts; and OCSv3 conformance.

The plan is stable for the exact decoded profile. It orders read-only inventory,
network, identity, storage, and observability checks before a single bootstrap
phase and binds that mutation phase to the declared rollback reference. The
CLI never applies the plan and never reads referenced values.

The JSON Schema enforces structure and the baseline three-node role counts.
The Go preflight is authoritative for cross-field rules, including declared
availability values, per-role failure-domain spread, and reference uniqueness.
The provider-neutral kubeadm renderer and stand verifier are documented in
[`kubeadm-control-plane-ha.md`](./kubeadm-control-plane-ha.md).
They are also available as standalone, strict JSON commands:

```sh
go run ./cmd/cloudring-site render-kubeadm --spec ./examples/kubeadm-bootstrap-spec.json
go run ./cmd/cloudring-site verify-kubeadm \
  --inventory /protected/run/kubeadm-stand-inventory.json \
  --one-server-loss-receipt /protected/run/unsigned-one-server-loss-receipt.json
```

Downstream adapters remain responsible for binding provider references,
performing the approved mutations, capturing current stand state, and passing
that captured state to the verifier. The public CLI neither resolves private
references nor performs provider mutations.

The control-plane endpoint must be implemented by an L2 or BGP VIP, provider
load balancer, or anycast service with health checking and a failover policy.
Pointing Cilium's `k8sServiceHost`, or an equivalent bootstrap client, at the
first control-plane node creates a circular outage: when that node is lost the
network agent cannot observe the API or move service leadership. The profile
therefore requires `controlPlaneAPIHA.endpointRef` and
`controlPlaneAPIHA.cniBootstrapEndpointRef` to be the same provider-owned
reference and rejects every declared per-node management or provisioning
address. `controlPlaneTransportDeviceRef` identifies the private or provider
transport device and `cniDeviceRefs` must contain it; omitting it can isolate
workloads from a surviving API server even when the virtual endpoint itself
moves correctly.

The references in `ipv4AddressRef` and `ipv6AddressRef` must both be included
in `servingCertificateSANRefs`, together with `endpointRef`. The
`servingCertificateLifecycle` must identify an idempotent reconfiguration
workflow, an exact rollback, and the one-server-loss acceptance. Its fixed
`one-node-at-a-time` rollout retains the previous certificate and key for
rollback, verifies the local static pod and the shared endpoint before
continuing, and stops on the first failure. The profile and evidence must not
contain private keys.

The referenced one-server-loss acceptance must remove the current API-endpoint
holder, prove that surviving network agents remain connected to the API, and
verify authenticated IPv4 and IPv6 API requests before the node is returned.
A profile is still a preflight-and-plan contract: its references do not
support a live release claim until their downstream implementations and the
failure test have been executed.

The host-runtime baseline is a capacity contract, not a prescribed operating
system. A Linux installer can satisfy it with a root-owned persistent sysctl
configuration such as `fs.inotify.max_user_instances = 1024`; an immutable or
API-managed operating system can use its native machine configuration. Apply
host changes one node at a time, retain the previous value for rollback, and
verify both the live value and persistence after restart. When KubeVirt is
enabled, acceptance must additionally prove every intended node has a Ready
`virt-handler`, is schedulable by KubeVirt, and advertises non-zero KVM, TUN,
and vhost-net device resources. A permanently privileged Kubernetes workload
that rewrites host sysctls is not a substitute for host provisioning.

Downstream repositories own concrete site-class profiles and provider adapter
implementations. They should validate their private profile in CI, bind each
reference through their own secret-safe inventory mechanism, implement the
declared phases, and retain live acceptance and rollback evidence outside the
public repository.

For upstream Kubernetes installations where an approved Gateway node is also a
kubeadm control-plane node, bootstrap must explicitly reconcile
`node.kubernetes.io/exclude-from-external-load-balancers`. Remove that label
only from the profile's declared `gateway` nodes, after a server-side dry-run
and a captured pre-state. Retain an exact rollback that restores the label.
Acceptance must fail closed unless the LoadBalancer advertises the declared
stable IPv4 and IPv6 service addresses, health checks remove or fail over an
unhealthy failure domain, both addresses remain reachable during that loss,
all surviving nodes remain Ready, and temporary probes are removed. Per-node
addresses published through DNS are useful discovery inputs but do not satisfy
this HA contract on their own.

Provider-neutral storage bases live under `deploy/kubernetes/storage`. Use the
Rook-Ceph RBD profile when three independent, dedicated raw devices are
available. Use the suspended Longhorn three-node profile for a compact cell
with enough supported filesystem capacity but no dedicated Ceph devices. Both
profiles require downstream host preflight, activation, backup/restore, node
loss, recovery, and cleanup evidence; a source render is never live readiness.

The reusable database profile lives under
`deploy/kubernetes/postgresql-ha`. It pairs the compact Longhorn profile with
three hard-separated PostgreSQL instances, synchronous quorum durability, the
official digest-pinned Barman Cloud CNPG-I plugin, continuous off-cell WAL,
scheduled base backups, and a separate isolated-recovery template. Downstream
installations still own the exact bucket/endpoint overlay, external credential
binding, sizing, retention and Object Lock enforcement, real isolated recovery,
application checksum, cleanup, cutover, and live primary-node-loss evidence.
They must also provision the two namespace-scoped OpenBao auth roles and CA
projections, keep recovery S3 and recovery-database credentials separate from
production, and replace the fail-closed TEST-NET recovery egress placeholders
with the exact private API and dedicated object-store CIDRs and ports. Because
raw NetworkPolicy `ipBlock` matching is sensitive to CNI DNAT ordering, the
effective on-wire destinations must be verified on the target site.

This slice provides profile preflight, deterministic planning, kubeadm
rendering, and captured-state verification contracts. It is not an installer,
does not prove that any provider site is reachable, and does not claim
production-grade readiness.
