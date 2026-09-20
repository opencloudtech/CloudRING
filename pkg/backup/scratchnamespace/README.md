# Restore scratch namespace lifecycle

`scratchnamespace` provides the portable Kubernetes namespace lifecycle for an
isolated restore. The caller supplies its existing durable operation checkpoint
store, a Kubernetes runner, clock, and context-aware wait function. It must
hold one exclusive operation lock across create, restore work, and cleanup.
The package does not introduce a second journal or select an installation,
credential source, backup target, or production namespace.

`Create` first proves absence and persists a create intent with the operation,
approval scope, required labels, and a random nonce. It server-dry-runs the
manifest, creates the namespace, and records the returned UID/resourceVersion.
A lost or malformed create response is reconciled by reading the namespace
and matching the durable nonce and ownership fields. A previously recorded
UID cannot be replaced on replay.

Register cleanup before calling `Create`. `Cleanup` can recover the uncertain
create window from the persisted intent after a process restart. It verifies
the current namespace's original UID and ownership, journals the current
resourceVersion, and submits a foreground raw API delete with both UID and
resourceVersion preconditions. A conflict leaves its intent intact; a later
replay may journal a fresh version of the same original UID. It never removes
the source backup or deletes a replacement namespace.

Completion requires two successful namespace-absence reads separated by at
least 30 seconds, followed by a durable cleanup receipt. Replay returns that
receipt only if the namespace is still absent. Missing or conflicting state,
failed reads, ownership drift, a replaced UID, and failed quiet windows remain
errors. Labels stored in the original create intent remain required for
cleanup; callers cannot relax them by passing different labels later.

This receipt proves the namespace lifecycle. Callers must separately verify
restored data, backup retention, network isolation, applicable volume/PV and
provider-resource cleanup, and installation health. A removed namespace alone
does not establish those outcomes.
