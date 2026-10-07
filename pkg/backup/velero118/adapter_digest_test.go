// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package velero118

import (
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
)

func TestCanonicalAdapterRequestJSONIsIndependentOfGoWireEscaping(t *testing.T) {
	t.Parallel()
	request := BackendRequest{
		SchemaVersion: AdapterRequestSchemaVersion, RequestDigestCanonicalization: AdapterRequestCanonicalization, Challenge: digest("challenge"), AdapterExecutableSHA256: digest("adapter"),
		Operation: "observe", SourceKind: "persistent-volume", ArtifactHandle: "volumé<&", ArtifactHandleSHA256: digest("handle"),
	}
	canonical, err := CanonicalAdapterRequestJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"adapterExecutableSha256":"` + digest("adapter") + `","artifactHandle":"volumé<&","artifactHandleSha256":"` + digest("handle") + `","challenge":"` + digest("challenge") + `","operation":"observe","requestDigestCanonicalization":"cloudring.restore-proof.adapter-canonical-json/v1","schemaVersion":"cloudring.restore-proof.adapter-request/v2","sourceKind":"persistent-volume"}`
	if string(canonical) != want {
		t.Fatalf("canonical request = %s\nwant = %s", canonical, want)
	}
	if AdapterRequestSHA256(request) != restoreproof.SHA256(want) {
		t.Fatal("adapter request digest is not bound to canonical JSON")
	}
}

func TestCanonicalAdapterRequestRejectsUnknownRequestType(t *testing.T) {
	t.Parallel()
	if payload, err := CanonicalAdapterRequestJSON(struct{ Value int }{Value: 1}); err == nil || payload != nil {
		t.Fatalf("unknown adapter request = %q, %v", payload, err)
	}
}
