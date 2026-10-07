// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package platformmanifest

import "testing"

func TestRuntimeChartSupplyChainRejectsDigestDrift(t *testing.T) {
	tests := []struct {
		name   string
		root   func(*testing.T) string
		verify func(string) (Report, error)
		old    string
	}{
		{"cert-manager OCI manifest", copyCertManagerProfile, VerifyCertManager, certManagerOCIManifestDigest},
		{"CloudNativePG OCI manifest", copyPostgreSQLHAProfile, VerifyPostgreSQLHA, cloudNativePGOCIManifestDigest},
		{"Longhorn release archive", copyLonghornThreeNodeProfile, VerifyLonghornThreeNode, "sha256:869bb20701b154473606f1e8967b27f34f2448a2dfe6eb8970f1cae6957384f5"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := test.root(t)
			data := readRepositoryFile(t, root, runtimeChartSupplyChainPath)
			data = replaceOnce(t, data, []byte(test.old), []byte("sha256:0000000000000000000000000000000000000000000000000000000000000000"))
			writeRepositoryFile(t, root, runtimeChartSupplyChainPath, data)
			if _, err := test.verify(root); err == nil {
				t.Fatal("runtime chart supply-chain digest drift was accepted")
			}
		})
	}
}

func TestRuntimeChartSupplyChainRejectsUnknownFields(t *testing.T) {
	root := copyCertManagerProfile(t)
	data := readRepositoryFile(t, root, runtimeChartSupplyChainPath)
	data = replaceOnce(t, data, []byte("{\n  \"schemaVersion\""), []byte("{\n  \"unreviewed\": true,\n  \"schemaVersion\""))
	writeRepositoryFile(t, root, runtimeChartSupplyChainPath, data)
	if _, err := VerifyCertManager(root); err == nil {
		t.Fatal("unknown supply-chain manifest field was accepted")
	}
}

func TestLonghornThreeNodeProfileRejectsVendorReceiptDrift(t *testing.T) {
	root := copyLonghornThreeNodeProfile(t)
	path := longhornVendoredRoot + "/UPSTREAM.json"
	data := readRepositoryFile(t, root, path)
	data = replaceOnce(t, data,
		[]byte("869bb20701b154473606f1e8967b27f34f2448a2dfe6eb8970f1cae6957384f5"),
		[]byte("0000000000000000000000000000000000000000000000000000000000000000"),
	)
	writeRepositoryFile(t, root, path, data)
	if _, err := VerifyLonghornThreeNode(root); err == nil {
		t.Fatal("Longhorn upstream receipt drift was accepted")
	}
}
