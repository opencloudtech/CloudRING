// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package platformmanifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

const (
	runtimeChartSupplyChainPath = "deploy/kubernetes/runtime-chart-supply-chain.json"
	longhornVendoredRoot        = "deploy/kubernetes/storage/longhorn-three-node/vendor"
	longhornVendoredChartPath   = longhornVendoredRoot + "/longhorn"
)

type runtimeChartSupplyChain struct {
	SchemaVersion string                 `json:"schemaVersion"`
	VerifiedAt    string                 `json:"verifiedAt"`
	Artifacts     []runtimeChartArtifact `json:"artifacts"`
	NonClaims     []string               `json:"nonClaims"`
}

type runtimeChartArtifact struct {
	ID                 string                 `json:"id"`
	Version            string                 `json:"version"`
	AppVersion         string                 `json:"appVersion,omitempty"`
	SourceKind         string                 `json:"sourceKind"`
	Source             string                 `json:"source"`
	ManifestDigest     string                 `json:"manifestDigest,omitempty"`
	ContentDigest      string                 `json:"contentDigest,omitempty"`
	ProvenanceDigest   string                 `json:"provenanceDigest,omitempty"`
	ArchiveDigest      string                 `json:"archiveDigest,omitempty"`
	VendoredPath       string                 `json:"vendoredPath,omitempty"`
	VendoredTreeDigest string                 `json:"vendoredTreeDigest,omitempty"`
	VendoredFileCount  int                    `json:"vendoredFileCount,omitempty"`
	UpstreamCommit     string                 `json:"upstreamCommit,omitempty"`
	License            string                 `json:"license"`
	LicenseDigest      string                 `json:"licenseDigest,omitempty"`
	OfficialSource     string                 `json:"officialSource"`
	Images             []runtimeImageArtifact `json:"images,omitempty"`
}

type runtimeImageArtifact struct {
	Key        string `json:"key"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
}

type longhornUpstreamReceipt struct {
	Name                    string `json:"name"`
	Version                 string `json:"version"`
	UpstreamRepository      string `json:"upstreamRepository"`
	UpstreamCommit          string `json:"upstreamCommit"`
	ReleaseArchive          string `json:"releaseArchive"`
	ReleaseArchiveSHA256    string `json:"releaseArchiveSha256"`
	OfficialIndex           string `json:"officialIndex"`
	License                 string `json:"license"`
	LicenseSHA256           string `json:"licenseSha256"`
	VendoredChartPath       string `json:"vendoredChartPath"`
	VendoredChartFileCount  int    `json:"vendoredChartFileCount"`
	VendoredChartTreeSHA256 string `json:"vendoredChartTreeSha256"`
}

var reviewedLonghornRuntimeImages = []runtimeImageArtifact{
	{Key: "longhorn.engine", Repository: "longhornio/longhorn-engine", Tag: "v1.12.0", Digest: "sha256:bc4a49e8f2b6b4bcdde0f6e465c0b0ac94acf6198840f9db039bedbbae67e905"},
	{Key: "longhorn.manager", Repository: "longhornio/longhorn-manager", Tag: "v1.12.0", Digest: "sha256:fd245bae2e8254ed475073410f8462e95fab8783dd12d1c084777b5ab53bfb86"},
	{Key: "longhorn.ui", Repository: "longhornio/longhorn-ui", Tag: "v1.12.0", Digest: "sha256:3870d52a2b0aa44e7f8a30d744cfe38a1a0bd130226d3f5d08795e76361ff0b7"},
	{Key: "longhorn.instanceManager", Repository: "longhornio/longhorn-instance-manager", Tag: "v1.12.0", Digest: "sha256:7dc270841c8a8855b9c7b192b53db05b6268318648108cea4b00c2e88eb85cbb"},
	{Key: "longhorn.shareManager", Repository: "longhornio/longhorn-share-manager", Tag: "v1.12.0", Digest: "sha256:cb9d6863e4c694d82ab35f91184d9555c536ed292dad0c7dec94cb655e05787e"},
	{Key: "longhorn.backingImageManager", Repository: "longhornio/backing-image-manager", Tag: "v1.12.0", Digest: "sha256:c480c397045e6a02bb1470cef759e2c3e2ff7fff4400bc3730dfd64446507d7e"},
	{Key: "longhorn.supportBundleKit", Repository: "longhornio/support-bundle-kit", Tag: "v0.0.86", Digest: "sha256:1342641f02ee00203998bb7afc00066e821197a7cf22fc43b7e02b6ab148f86d"},
	{Key: "csi.attacher", Repository: "longhornio/csi-attacher", Tag: "v4.12.0", Digest: "sha256:a814aa4784197116983ea13e376fc691e000a390de9d0b9fca2bc4a2fb7c4a1f"},
	{Key: "csi.provisioner", Repository: "longhornio/csi-provisioner", Tag: "v5.3.0-20260514", Digest: "sha256:05c4017e4df7f8f690d6578f975f1eba94624d1b6a675d88c5f508ab6a27152b"},
	{Key: "csi.nodeDriverRegistrar", Repository: "longhornio/csi-node-driver-registrar", Tag: "v2.17.0", Digest: "sha256:29f7cfd519008fe8f8dff5e79db43f70d65c43a89c08f1bafbb199ca90df79f0"},
	{Key: "csi.resizer", Repository: "longhornio/csi-resizer", Tag: "v2.1.0-20260514", Digest: "sha256:7f203c1f195445e8ca8be258cd6179c284885a6c1b5287e6c0e33870e9083f8a"},
	{Key: "csi.snapshotter", Repository: "longhornio/csi-snapshotter", Tag: "v8.5.0-20260514", Digest: "sha256:df4ba2075c00c5193821d43caf11c6f6556310247723365e9916e409799ce029"},
	{Key: "csi.livenessProbe", Repository: "longhornio/livenessprobe", Tag: "v2.19.0", Digest: "sha256:d0cb76b565ba9d36da0dc2b38e2b6a49a0ae4fe067b03086110682f32c600318"},
}

var expectedRuntimeChartSupplyChain = runtimeChartSupplyChain{
	SchemaVersion: "cloudring.runtime-chart-supply-chain/v1",
	VerifiedAt:    "2026-07-23T05:36:00Z",
	Artifacts: []runtimeChartArtifact{
		{
			ID: "cert-manager", Version: "v1.21.0", SourceKind: "oci-helm-chart",
			Source:           "oci://quay.io/jetstack/charts/cert-manager",
			ManifestDigest:   "sha256:cd55fea42658e54abc25e85a0bc1de229925a5006445f916bfd2c6dc80ac3613",
			ContentDigest:    "sha256:9c2c6fabf3cf8fe14dacb016f37c819b66bc2c79e8b7acde4573d45ec141fb97",
			ProvenanceDigest: "sha256:83dcfe267afdbc92613bd7879c6854199a6bc0cca9c62edb19d5a932be102307",
			License:          "Apache-2.0", OfficialSource: "https://cert-manager.io/docs/installation/helm/",
		},
		{
			ID: "cloudnative-pg", Version: "0.29.0", AppVersion: "1.30.0", SourceKind: "oci-helm-chart",
			Source:           "oci://ghcr.io/cloudnative-pg/charts/cloudnative-pg",
			ManifestDigest:   "sha256:209c588b902982bf283a0073db83edd422d9710a2c8a670fe57c0329abe789a4",
			ContentDigest:    "sha256:668e065ff53508d58238788fd35b355a925060843629a951df0e6a9362e6d32f",
			ProvenanceDigest: "sha256:9426303423d3b3a303219764468ca15952846928429b2dd6578e60d242fc1a8e",
			License:          "Apache-2.0", OfficialSource: "https://cloudnative-pg.io/charts/",
		},
		{
			ID: "cloudnative-pg-barman-cloud", Version: "0.7.0", AppVersion: "v0.13.0", SourceKind: "oci-helm-chart",
			Source:           "oci://ghcr.io/cloudnative-pg/charts/plugin-barman-cloud",
			ManifestDigest:   "sha256:5d31605cad886f93abb7cd9884170d74ece913fe8b95c74b127ec5e8bcd2b2b6",
			ContentDigest:    "sha256:eb2d840e2b22fb2678c4554efdfb3a23cfafb8f8597ef84657c433bbc6a327ea",
			ProvenanceDigest: "sha256:49a423b8a209f252beef4f601795eb005a850595ccd3d1ec0fc7201b5f0bed65",
			License:          "Apache-2.0", OfficialSource: "https://cloudnative-pg.io/plugin-barman-cloud/docs/installation/",
			Images: []runtimeImageArtifact{
				{Key: "manager", Repository: "ghcr.io/cloudnative-pg/plugin-barman-cloud", Tag: "v0.13.0", Digest: "sha256:71589dbac582333442812b07b31f7ea4d00324a8358aac7ca507dabf9f4b6c96"},
				{Key: "sidecar", Repository: "ghcr.io/cloudnative-pg/plugin-barman-cloud-sidecar", Tag: "v0.13.0", Digest: "sha256:990361af3319f9e23aafa0f6d7981f99bf1f69b4e6a85cf1bc7d71d6f09bb288"},
			},
		},
		{
			ID: "longhorn", Version: "1.12.0", AppVersion: "v1.12.0", SourceKind: "vendored-helm-chart",
			Source:             "https://github.com/longhorn/charts/releases/download/longhorn-1.12.0/longhorn-1.12.0.tgz",
			ArchiveDigest:      "sha256:869bb20701b154473606f1e8967b27f34f2448a2dfe6eb8970f1cae6957384f5",
			VendoredPath:       longhornVendoredChartPath,
			VendoredTreeDigest: "sha256:261f3fd1471c816de9153de46ef10a8b68df2a72faa605a7684630a3a40e583a",
			VendoredFileCount:  42,
			UpstreamCommit:     "f8def0504bf3f5f26c342941c9e4532b44830ebe",
			License:            "Apache-2.0",
			LicenseDigest:      "sha256:c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
			OfficialSource:     "https://longhorn.io/docs/1.12.0/deploy/upgrade/longhorn-manager/",
			Images:             reviewedLonghornRuntimeImages,
		},
	},
	NonClaims: []string{
		"Registry and release-archive digest verification does not prove a live reconciliation or workload health.",
		"The Barman Cloud Plugin release remains suspended; pinned chart and images do not prove WAL archival, base-backup recovery, bucket retention, or object lock.",
		"The Longhorn release remains suspended; its exact upstream Git commit does not prove remote Git availability or offline installation.",
	},
}

func requireRuntimeChartArtifact(root *os.Root, id string) (runtimeChartArtifact, error) {
	data, err := readRegular(root, runtimeChartSupplyChainPath)
	if err != nil {
		return runtimeChartArtifact{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest runtimeChartSupplyChain
	if err := decoder.Decode(&manifest); err != nil {
		return runtimeChartArtifact{}, fmt.Errorf("decode runtime chart supply-chain manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return runtimeChartArtifact{}, errors.New("runtime chart supply-chain manifest must contain exactly one JSON document")
	}
	if !reflect.DeepEqual(manifest, expectedRuntimeChartSupplyChain) {
		return runtimeChartArtifact{}, errors.New("runtime chart supply-chain manifest differs from the exact reviewed artifacts")
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.ID == id {
			return artifact, nil
		}
	}
	return runtimeChartArtifact{}, fmt.Errorf("runtime chart artifact %q is missing", id)
}

func verifyVendoredLonghornChart(root *os.Root, artifact runtimeChartArtifact) (int, error) {
	if artifact.ID != "longhorn" || artifact.SourceKind != "vendored-helm-chart" || artifact.VendoredPath != longhornVendoredChartPath {
		return 0, errors.New("Longhorn vendored artifact contract is invalid")
	}
	paths, err := confinedRegularFiles(root, longhornVendoredChartPath)
	if err != nil {
		return 0, err
	}
	if len(paths) != artifact.VendoredFileCount {
		return 0, errors.New("Longhorn vendored chart file inventory is incomplete")
	}
	hash := sha256.New()
	for _, relative := range paths {
		data, readErr := readRegular(root, filepath.Join(longhornVendoredChartPath, relative))
		if readErr != nil {
			return 0, readErr
		}
		contentHash := sha256.Sum256(data)
		_, _ = hash.Write([]byte(filepath.ToSlash(relative)))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(hex.EncodeToString(contentHash[:])))
		_, _ = hash.Write([]byte{'\n'})
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != artifact.VendoredTreeDigest {
		return 0, errors.New("Longhorn vendored chart tree digest differs from the reviewed release")
	}
	chartData, err := readRegular(root, filepath.Join(longhornVendoredChartPath, "Chart.yaml"))
	if err != nil {
		return 0, err
	}
	var chart map[string]any
	if err := decodeOne(chartData, &chart); err != nil ||
		!exactMappingKeys(chart, "apiVersion", "appVersion", "description", "home", "icon", "keywords", "kubeVersion", "maintainers", "name", "sources", "version") ||
		nestedString(chart, "name") != "longhorn" || nestedString(chart, "version") != "1.12.0" || nestedString(chart, "appVersion") != "v1.12.0" {
		return 0, errors.New("Longhorn vendored Chart.yaml identity is invalid")
	}
	if err := verifyLonghornVendorProvenance(root, artifact); err != nil {
		return 0, err
	}
	if err := verifyLonghornChartImageReferences(root, paths, artifact.Images); err != nil {
		return 0, err
	}
	return len(paths) + 2, nil
}

var longhornChartImageReferencePattern = regexp.MustCompile(`[.]Values[.]image[.]([A-Za-z0-9.]+)[.](repository|tag)\b`)

func verifyLonghornChartImageReferences(root *os.Root, paths []string, images []runtimeImageArtifact) error {
	references := map[string]map[string]bool{}
	for _, relative := range paths {
		if !strings.HasPrefix(filepath.ToSlash(relative), "templates/") {
			continue
		}
		data, err := readRegular(root, filepath.Join(longhornVendoredChartPath, relative))
		if err != nil {
			return err
		}
		for _, match := range longhornChartImageReferencePattern.FindAllSubmatch(data, -1) {
			key := string(match[1])
			if references[key] == nil {
				references[key] = map[string]bool{}
			}
			references[key][string(match[2])] = true
		}
	}
	// The OpenShift OAuth proxy is conditional and has an empty repository/tag
	// while this provider-neutral profile keeps ingress disabled.
	delete(references, "openshift.oauthProxy")
	if len(references) != len(images) {
		return errors.New("Longhorn rendered image reference inventory is incomplete")
	}
	for _, image := range images {
		fields, ok := references[image.Key]
		if !ok || !fields["repository"] || !fields["tag"] || len(fields) != 2 {
			return errors.New("Longhorn rendered image reference inventory differs from the reviewed images")
		}
		delete(references, image.Key)
	}
	if len(references) != 0 {
		return errors.New("Longhorn chart contains an unreviewed runtime image reference")
	}
	return nil
}

func verifyLonghornVendorProvenance(root *os.Root, artifact runtimeChartArtifact) error {
	license, err := readRegular(root, filepath.Join(longhornVendoredRoot, "LICENSE"))
	if err != nil {
		return err
	}
	licenseHash := sha256.Sum256(license)
	if "sha256:"+hex.EncodeToString(licenseHash[:]) != artifact.LicenseDigest || !bytes.Contains(license, []byte("Apache License")) {
		return errors.New("Longhorn vendored license is invalid")
	}
	receiptData, err := readRegular(root, filepath.Join(longhornVendoredRoot, "UPSTREAM.json"))
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(receiptData))
	decoder.DisallowUnknownFields()
	var receipt longhornUpstreamReceipt
	if err := decoder.Decode(&receipt); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("Longhorn vendored provenance receipt is invalid")
	}
	expected := longhornUpstreamReceipt{
		Name: "longhorn", Version: artifact.Version,
		UpstreamRepository: "https://github.com/longhorn/charts", UpstreamCommit: artifact.UpstreamCommit,
		ReleaseArchive: artifact.Source, ReleaseArchiveSHA256: strings.TrimPrefix(artifact.ArchiveDigest, "sha256:"),
		OfficialIndex: "https://charts.longhorn.io/index.yaml", License: artifact.License,
		LicenseSHA256: strings.TrimPrefix(artifact.LicenseDigest, "sha256:"), VendoredChartPath: "longhorn",
		VendoredChartFileCount:  artifact.VendoredFileCount,
		VendoredChartTreeSHA256: strings.TrimPrefix(artifact.VendoredTreeDigest, "sha256:"),
	}
	if !reflect.DeepEqual(receipt, expected) {
		return errors.New("Longhorn vendored provenance differs from the reviewed upstream release")
	}
	return nil
}

func confinedRegularFiles(root *os.Root, directory string) ([]string, error) {
	var paths []string
	var walk func(string, string) error
	walk = func(current, relativePrefix string) error {
		dir, err := root.Open(current)
		if err != nil {
			return errors.New("open vendored chart directory")
		}
		entries, readErr := dir.ReadDir(-1)
		closeErr := dir.Close()
		if readErr != nil || closeErr != nil {
			return errors.New("read vendored chart directory")
		}
		for _, entry := range entries {
			relative := filepath.Join(relativePrefix, entry.Name())
			path := filepath.Join(directory, relative)
			if entry.IsDir() {
				if err := walk(path, relative); err != nil {
					return err
				}
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return errors.New("vendored chart contains a symlink or non-regular file")
			}
			paths = append(paths, relative)
		}
		return nil
	}
	if err := walk(directory, ""); err != nil {
		return nil, err
	}
	sort.Slice(paths, func(i, j int) bool { return filepath.ToSlash(paths[i]) < filepath.ToSlash(paths[j]) })
	return paths, nil
}
