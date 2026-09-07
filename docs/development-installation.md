# Disposable public development installation

`cloudring dev` creates a real, empty CloudRING provider in one new Linux VM.
The VM runs upstream kubeadm Kubernetes, containerd, Cilium, PostgreSQL and the
public API/portal server. PostgreSQL stores the installation and browser
sessions durably. The initial product list is empty because this slice has not
installed a compute, storage or managed Kubernetes product.

This profile is development-only. It has one control-plane node, one database
instance, a short-lived installation CA and one bootstrap operator. The
production profile parser rejects its document and credentials. Its readiness
receipt always contains `productionReady: false`.

## Supported prerequisite substrate

The first supported adapter uses an existing, operator-selected Linux amd64
KubeVirt cluster with CDI, Cilium policy enforcement and Longhorn. It creates a
new namespace, a nonpreempting priority class when needed, quota, isolation
policy, cloud-init Secret, DataVolume and VM. It adopts none of the existing
VMs, namespaces, credentials or volumes.

The selected node must advertise real KVM, TUN and vhost-net devices and have
fresh reservation headroom for the requested VM plus overhead. The initial
guest has 4 vCPU, 8 GiB RAM and a 60 GiB root disk. A Mac can be the client; the
guest and upstream Kubernetes execute on Linux. Nested KVM inside the guest
is a separate requirement for a later compute-product slice.

The selected Longhorn storage class must use `Delete` reclaim. The operator
checks actual disk placement, replicas, free space and failure headroom before
launch; scheduler request headroom is a separate check. Destruction waits for
the recorded PVC, PV and Longhorn volume identity to disappear. It does not
clear finalizers or force-delete a backend volume.

The operator supplies one exact inline kubeconfig context on stdin. It must
contain its API server, CA, and either client certificate/key or bearer token.
The command rejects multiple contexts, exec/auth plugins, credential file
references, TLS bypasses and proxy settings. It does not read `KUBECONFIG`,
other contexts, ambient tokens or a user's default Kubernetes configuration.
The API server and `kube-system` UID must match the profile.

The credential needs read access to nodes, pods, service CIDRs, CRDs, storage
classes, Cilium readiness, PVs and Longhorn volumes; read/create/delete access
for the exact planned objects; and the owned VMI's port-forward subresource.
Cleanup also needs discovery and list/read access to every deletable resource
type inside the new namespace. That complete inventory prevents deletion of
unrecognized content. Namespace and priority-class creation permissions belong
to the selected substrate administrator's admission/RBAC policy.

## Use the accepted public artifacts

Obtain `cloudring-dev-artifacts.json`, `cloudring-dev-egress-domains.json` and the client from the selected signed,
immutable C02 prerelease. The BOM contains exact upstream artifact hashes,
image digests, the accepted source commit, and the direct Linux installer
asset's URL and SHA-256. Follow [release verification](releasing.md) to verify
the source, release workflow and provenance for this exact release. Do not
substitute `latest` images or an unverified BOM.

Linux users can use the verified `cloudring-linux-amd64` asset as `cloudring`.
Linux and macOS users can also build the client from the clean public release
checkout with Go 1.26.8 or a newer supported security release:

```sh
go build -o ./cloudring ./cmd/cloudring
```

The client independently downloads and verifies the release's Linux installer
before transferring it to the guest. It does not try to execute a macOS binary
there, install host packages, invoke Python, or inherit shell authentication.

## Construct the explicit operator profile

Keep the downloaded BOM unchanged. Supply `target.json` with the exact
`apiServer`, `kubeSystemUID`, `namespace`, `virtualMachine`, `node`,
`storageClass` and `priorityClass`. The namespace must be
`cloudring-dev-<installationID>`. Choose that same name for `priorityClass` to
create a new owned class, or select an existing nonpositive class with
`preemptionPolicy: Never`. Existing names are not evidence of ownership.

Supply `network.json` with `guestCIDR`, `podCIDR`, `serviceCIDR`, `publicOrigin`
and `egressDomains`. The guest network is a canonical private IPv4 `/30`.
The child pod and service networks are canonical private IPv4 `/16`–`/24`
networks. All three must be distinct and avoid the substrate's node addresses,
pod networks and service networks. The browser origin is
`https://<chosen-name>.localhost:<chosen-unprivileged-port>`.

Populate `egressDomains` from the verified release companion
`cloudring-dev-egress-domains.json`. It contains the sorted, unique public
registry and CDN domains required by that exact BOM, including redirect and
registry authentication destinations. Keep the companion with its release
signatures and provenance; do not guess a shorter domain list. The namespace policy allows DNS
to the substrate's CoreDNS and HTTPS to those destinations. It denies HTTPS
to private, loopback, link-local and shared-address ranges, and denies access
to node and API-server identities. Verify the real positive download path and
negative neighbor/API-server paths during acceptance; a rendered policy is
not evidence that enforcement works.

Create `profile.json` from those public artifact pins and explicit operator
inputs. `INSTALLATION_ID` is the chosen 3–40 character lowercase DNS label.
The following command is a deterministic transformation, not an installer:

```sh
jq -n \
  --arg id "$INSTALLATION_ID" \
  --slurpfile target target.json \
  --slurpfile network network.json \
  --slurpfile artifacts cloudring-dev-artifacts.json \
  '{apiVersion:"cloudring.org/v1alpha1",kind:"CloudRINGDevelopmentInstallation",
    profile:"development",installationID:$id,target:$target[0],network:$network[0],
    guest:{cpus:4,memoryMiB:8192,diskGiB:60},artifacts:$artifacts[0]}' \
  > profile.json

./cloudring dev validate --profile profile.json --offline
./cloudring dev validate --profile profile.json < "$SUBSTRATE_CONTEXT_FILE"
```

`SUBSTRATE_CONTEXT_FILE` refers to the operator's protected, single-context
inline credential input. Shell redirection supplies it through stdin; its
path and contents are not command arguments or saved installation state.
An equivalent protected credential pipe can replace the redirection.

The offline command validates the strict profile and prints the deterministic
plan. The online command also checks the actual cluster identity, APIs,
nonoverlapping networks, healthy node, KVM devices, reservation headroom,
storage class and Cilium readiness. Its report explicitly retains the
operator's disk-placement and actual network-denial acceptance requirements.

## Create, use and repeat

Choose a new state-directory name under an existing directory owned by the
current user. The installer creates it privately and locks it exclusively.
It refuses an unrelated existing directory, altered ownership marker,
symlink/hardlink credential file or a different profile for the same state.

```sh
./cloudring dev create --profile profile.json --state ./dev-state \
  --timeout 45m < "$SUBSTRATE_CONTEXT_FILE"

./cloudring dev create --profile profile.json --state ./dev-state \
  --timeout 45m < "$SUBSTRATE_CONTEXT_FILE"

./cloudring dev status --profile profile.json --state ./dev-state \
  < "$SUBSTRATE_CONTEXT_FILE"
```

The second create reuses the recorded resource UIDs, credentials, certificates
and PostgreSQL state. It does not create a second VM or reinitialize the
database. A pending ownership journal is persisted before each API create, so
a lost response can be reconciled against the same nonce and exact requested
fields. A foreign or replaced object stops the operation.

Success requires the actual guest bootstrap, verified HTTPS provider identity,
accepted source revision, writable PostgreSQL, and rejection of absent and
foreign operator tokens. Status queries those live paths again; the local
`ready` journal flag alone cannot make a provider ready. JSON progress and
receipts contain identities and checks, never credentials or raw API bodies.

To use the portal, keep the connection in the foreground:

```sh
./cloudring dev status --profile profile.json --state ./dev-state \
  --connect --timeout 2h < "$SUBSTRATE_CONTEXT_FILE"
```

Open the exact `publicOrigin` printed in the receipt. Trust the installation's
`dev-state/api-ca.pem` only in the browser context used for this development
installation, and enter the operator token from the private
`dev-state/operator-token` file. The CLI already verifies that CA and hostname
independently. It never changes global trust, DNS, proxy settings or public
ingress. Only the local IPv4 loopback listener is exposed; the upstream connection
uses the selected API server's TLS and the guest's independently pinned SSH
host key. Stop the foreground command before destroy/reset.

The installation CA is local to this provider, and its server certificates
expire after seven days. Recreate this disposable environment when they
expire. This is not the production certificate-rotation path.

## Diagnose, cancel and remove

```sh
./cloudring dev diagnose --profile profile.json --state ./dev-state \
  < "$SUBSTRATE_CONTEXT_FILE"

./cloudring dev destroy --profile profile.json --state ./dev-state \
  --timeout 45m < "$SUBSTRATE_CONTEXT_FILE"

./cloudring dev create --profile profile.json --state ./dev-state \
  --timeout 45m < "$SUBSTRATE_CONTEXT_FILE"
```

Ctrl-C or `--timeout` stops the client and closes its connections. The guest
bootstrap has its own deadline and journal. Retry the same create to resume
the owned installation, or destroy it. Never delete the local state directory
first: it holds the ownership identities needed to verify cleanup.

Destroy inventories all discoverable namespaced resource types before deleting
anything. Unrecognized content, changed UIDs, failed API reads or a remaining
Longhorn backend prevent a green receipt. Normal foreground deletion must
finish; the command does not remove finalizers or bypass storage reclaim.
Only then does it remove its private local files and report
`zeroOwnedResidue: true`. Keep that receipt with the profile and release BOM.

Destroy with an already absent local journal makes no changes and reports
`phase: absent`; it does not invent another verified zero-residue receipt.
`cloudring dev reset` performs the same verified destroy followed by create
with a new ownership identity. It is explicitly destructive to this one
development environment and its database.

## Acceptance for this slice

Use the same public release/profile for clean create, repeated create, a real
guest/runtime restart, API and CLI denials, browser login/logout and persisted
session behavior, database outage/recovery, cancellation/resume, destroy and
recreate. Verify real network isolation alongside the existing hub. Record
the source and artifact digests, created UIDs, actual responses, observations
and complete cleanup receipt. Both downstream consumers pin this public
release and execute create/status/destroy; no private source checkout is an
installer prerequisite.

Go contract tests validate boundary behavior, identity guards and failure
recovery. They are not evidence that a live VM, database, portal, network
policy or storage backend passed the acceptance sequence.
