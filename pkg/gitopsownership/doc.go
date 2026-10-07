// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package gitopsownership defines a provider-neutral, fail-closed contract for
// proving that an accepted Flux source artifact and its exact Kustomization
// roots uniquely own the declared critical resource families.
//
// Version 2 is closed-world only inside each explicitly declared
// API-resource-and-namespace scope. Collectors list those scopes without label
// selectors and prove bounded pagination completeness. This does not claim
// whole-cluster ownership: unrelated kinds and namespaces remain outside the
// contract. Reviewed non-CloudRING occupants of a shared scope must be declared
// as externalObjects and must not be Flux-owned by a selected root.
//
// The package validates evidence and provides provider-neutral collection
// mechanics. Provider credentials, live bindings, and all mutations remain the
// responsibility of downstream installations.
package gitopsownership
