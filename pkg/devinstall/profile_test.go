// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/siteprofile"
)

// These source-only pins exercise the parser. No backend consumes them and no
// unit test declares an image download, guest or database to be ready.
func testProfile() Profile {
	download := func(version string) Download {
		return Download{Version: version, URL: "https://github.com/example/project/releases/download/" + version + "/linux-amd64.tar.gz", SHA256: strings.Repeat("a", 64)}
	}
	profile := Profile{APIVersion: APIVersion, Kind: Kind, Profile: Development, InstallationID: "parser-test",
		Target: Target{APIServer: "https://kubevirt.example.test:6443", KubeSystemUID: "12345678-1234-4321-8123-123456789abc",
			Namespace: "cloudring-dev-parser-test", VirtualMachine: "development-linux", Node: "selected-node",
			StorageClass: "selected-delete-storage", PriorityClass: "cloudring-dev-parser-test"},
		Guest: Guest{CPUs: 4, MemoryMiB: 8192, DiskGiB: 60},
		Network: Network{GuestCIDR: ipv4Prefix([4]byte{192, 168, 234}, 30), PodCIDR: ipv4Prefix([4]byte{172, 30}, 16), ServiceCIDR: ipv4Prefix([4]byte{172, 31}, 16),
			PublicOrigin: (&url.URL{Scheme: "https", Host: net.JoinHostPort("parser-test.localhost", "18443")}).String(), EgressDomains: []string{"github.com", "quay.io"}},
		Artifacts: BOM{SourceCommit: strings.Repeat("b", 40),
			Installer:       Download{Version: "v0.2.0-c02.1", URL: "https://github.com/opencloudtech/CloudRING/releases/download/v0.2.0-c02.1/cloudring-linux-amd64", SHA256: strings.Repeat("a", 64)},
			GuestImage:      "quay.io/capk/ubuntu-2404-container-disk@sha256:" + strings.Repeat("c", 64),
			RuntimeImage:    "ghcr.io/opencloudtech/cloudring-server@sha256:" + strings.Repeat("d", 64),
			PostgreSQLImage: "docker.io/library/postgres:18.6@sha256:" + strings.Repeat("e", 64),
			Kubeadm:         download("v1.35.6"), Kubelet: download("v1.35.6"), Kubectl: download("v1.35.6"),
			Containerd: download("v2.2.2"), Runc: download("v1.3.4"), CNIPlugins: download("v1.8.0"),
			CRICTL: download("v1.35.0"), Helm: download("v3.19.0"), CiliumChart: download("v1.19.0"),
			CiliumImage:         "quay.io/cilium/cilium@sha256:" + strings.Repeat("f", 64),
			CiliumOperatorImage: "quay.io/cilium/operator-generic@sha256:" + strings.Repeat("a", 64),
		}}
	for _, name := range []string{"kube-apiserver:v1.35.6", "kube-controller-manager:v1.35.6", "kube-scheduler:v1.35.6", "kube-proxy:v1.35.6", "coredns/coredns:v1.13.1", "etcd:3.6.6-0", "pause:3.10.1"} {
		profile.Artifacts.KubernetesImages = append(profile.Artifacts.KubernetesImages, ImagePin{Name: "registry.k8s.io/" + name, Digest: "sha256:" + strings.Repeat("a", 64)})
	}
	return profile
}

func TestDevelopmentProfileCannotEnterProduction(t *testing.T) {
	profile := testProfile()
	if err := Validate(profile, Development); err != nil {
		t.Fatal(err)
	}
	if err := Validate(profile, "production"); !errors.Is(err, ErrProduction) {
		t.Fatalf("production caller accepted development: %v", err)
	}
	payload, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := siteprofile.Parse(bytes.NewReader(payload)); err == nil {
		t.Fatal("production site parser accepted a development profile")
	}
	profile.Profile = "production"
	if err := Validate(profile, Development); !errors.Is(err, ErrProduction) {
		t.Fatalf("development command accepted production mode: %v", err)
	}
}

func TestProfileRejectsUnownedNetworksMutableArtifactsAndAmbiguousInputs(t *testing.T) {
	cases := map[string]func(*Profile){
		"namespace outside installation": func(p *Profile) { p.Target.Namespace = "default" },
		"ambiguous cluster identity":     func(p *Profile) { p.Target.KubeSystemUID = "00000000-0000-0000-0000-000000000000" },
		"URL credentials": func(p *Profile) {
			p.Target.APIServer = (&url.URL{Scheme: "https", Host: "cluster.example.test:6443", User: url.UserPassword("synthetic", "synthetic")}).String()
		},
		"missing resources":          func(p *Profile) { p.Guest.CPUs = 0 },
		"overlapping child networks": func(p *Profile) { p.Network.ServiceCIDR = ipv4Prefix([4]byte{172, 30, 1}, 24) },
		"public guest network":       func(p *Profile) { p.Network.GuestCIDR = "8.8.8.0/30" },
		"noncanonical network":       func(p *Profile) { p.Network.PodCIDR = ipv4Prefix([4]byte{172, 30, 1, 1}, 16) },
		"non TLS origin": func(p *Profile) {
			p.Network.PublicOrigin = (&url.URL{Scheme: "http", Host: net.JoinHostPort("parser-test.localhost", "18443")}).String()
		},
		"credential in origin query": func(p *Profile) {
			query := url.Values{}
			query.Set("token", "synthetic")
			p.Network.PublicOrigin += "?" + query.Encode()
		},
		"internal egress":       func(p *Profile) { p.Network.EgressDomains = []string{"svc.cluster.local"} },
		"mutable runtime image": func(p *Profile) { p.Artifacts.RuntimeImage = "ghcr.io/opencloudtech/cloudring-server:latest" },
		"foreign runtime": func(p *Profile) {
			p.Artifacts.RuntimeImage = "private.example.test/runtime@sha256:" + strings.Repeat("a", 64)
		},
		"missing artifact hash":     func(p *Profile) { p.Artifacts.Kubeadm.SHA256 = "" },
		"inconsistent kubelet":      func(p *Profile) { p.Artifacts.Kubelet.Version = "v1.34.1" },
		"unlisted Kubernetes image": func(p *Profile) { p.Artifacts.KubernetesImages[6].Name = "registry.k8s.io/other:v1" },
		"missing Kubernetes image":  func(p *Profile) { p.Artifacts.KubernetesImages = p.Artifacts.KubernetesImages[:6] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			profile := testProfile()
			mutate(&profile)
			if err := Validate(profile, Development); err == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
	payload, err := json.Marshal(testProfile())
	if err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string][]byte{
		"unknown field":      append([]byte(`{"productionOverride":true,`), payload[1:]...),
		"duplicate field":    append([]byte(`{"profile":"production",`), payload[1:]...),
		"multiple documents": append(append([]byte(nil), payload...), payload...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(bytes.NewReader(changed)); err == nil {
				t.Fatal("ambiguous input accepted")
			}
		})
	}
}

func TestPlanIsDeterministicAndDoesNotContainRuntimeCredentials(t *testing.T) {
	profile := testProfile()
	first, err := BuildPlan(profile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPlan(profile)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("plan changed: %v", err)
	}
	if first.ProductionReady || first.GuestAddress != netip.AddrFrom4([4]byte{192, 168, 234, 2}).String() || len(first.Objects) != 7 {
		t.Fatalf("incorrect scope: %#v", first)
	}
	for _, object := range first.Objects {
		if object.UID != "" || object.Namespace != "" && object.Namespace != profile.Target.Namespace {
			t.Fatalf("unowned scope: %#v", object)
		}
	}
	payload, _ := json.Marshal(first)
	for _, forbidden := range []string{"operatorToken", "Password", "PrivateKey", "databaseDSN"} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("plan exposes %s", forbidden)
		}
	}
}
