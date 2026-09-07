// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func guestBootstrapTestState(t *testing.T) State {
	t.Helper()
	profile := testProfile()
	credentials, err := newCredentials(profile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return State{APIVersion: stateSchema, InstallationID: profile.InstallationID, OwnerNonce: strings.Repeat("c", 64),
		ProfileSHA256: Fingerprint(profile), Profile: profile, Credentials: credentials, Sequence: 2, Phase: "creating"}
}

func TestGuestBootstrapRejectsChangedOwnershipBeforeExecution(t *testing.T) {
	state := guestBootstrapTestState(t)
	encode := func(value State) []byte {
		payload, err := json.Marshal(guestBootstrapInput{APIVersion: "cloudring.development-bootstrap/v1", State: value})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	payload := encode(state)
	if _, err := parseGuestBootstrap(bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*State){
		"production":           func(state *State) { state.Profile.Profile = "production" },
		"foreign-installation": func(state *State) { state.InstallationID = "foreign-installation" },
		"changed-profile":      func(state *State) { state.Profile.Guest.CPUs++ },
		"missing-nonce":        func(state *State) { state.OwnerNonce = "" },
		"missing-commit":       func(state *State) { state.Sequence = 0 },
		"destroying":           func(state *State) { state.Phase = "destroying" },
		"expired-certificate":  func(state *State) { state.Credentials.CertificateExpiresAt = time.Now().Add(-time.Minute) },
		"credential-injection": func(state *State) { state.Credentials.DatabaseOwnerPassword = "quoted SQL value" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := state
			change(&changed)
			if _, err := parseGuestBootstrap(bytes.NewReader(encode(changed))); err == nil {
				t.Fatal("accepted invalid bootstrap identity")
			}
		})
	}
	for _, invalid := range [][]byte{append(append([]byte{}, payload...), []byte("{}")...), bytes.Replace(payload, []byte(`"state":`), []byte(`"unexpected":true,"state":`), 1), []byte(strings.Repeat(" ", maximumStateBytes+1))} {
		if _, err := parseGuestBootstrap(bytes.NewReader(invalid)); err == nil {
			t.Fatal("accepted ambiguous or oversized bootstrap request")
		}
	}
	if runtime.GOOS != "linux" {
		if err := BootstrapGuest(context.Background(), bytes.NewReader(payload), io.Discard); err == nil {
			t.Fatal("client host accepted guest bootstrap")
		}
	}
}

func TestGuestImageAliasRejectsDigestRebinding(t *testing.T) {
	image := ImagePin{Name: "registry.k8s.io/kube-proxy:v1.35.8", Digest: "sha256:" + strings.Repeat("a", 64)}
	row := image.Name + " application/vnd.oci.image.index.v1+json " + image.Digest + " 22MiB linux/amd64 -\n"
	if present, err := guestAliasPresent([]byte("REF TYPE DIGEST SIZE PLATFORMS LABELS\n"+row), image); err != nil || !present {
		t.Fatal("exact immutable alias not recognized", err)
	}
	if present, err := guestAliasPresent(nil, image); err != nil || present {
		t.Fatal("absent alias treated as present")
	}
	for _, payload := range []string{image.Name + " malformed\n", strings.Replace(row, image.Digest, "sha256:"+strings.Repeat("b", 64), 1)} {
		if _, err := guestAliasPresent([]byte(payload), image); err == nil {
			t.Fatal("rebound or malformed alias accepted")
		}
	}
}

func TestGuestControlPlaneKeepsDevelopmentPortsOnLoopback(t *testing.T) {
	state := guestBootstrapTestState(t)
	payload, err := guestKubeadmConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	documents := map[string]map[string]any{}
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		kind, _ := document["kind"].(string)
		documents[kind] = document
	}
	proxy := documents["KubeProxyConfiguration"]
	if proxy["mode"] != "iptables" || proxy["iptables"].(map[string]any)["localhostNodePorts"] != true {
		t.Fatal("localhost forwarding is not explicitly configured")
	}
	addresses := proxy["nodePortAddresses"].([]any)
	if len(addresses) != 1 || addresses[0] != ipv4Prefix([4]byte{127}, 8) {
		t.Fatal("node ports exposed outside guest loopback")
	}
	init := documents["InitConfiguration"]
	if init["nodeRegistration"].(map[string]any)["imagePullPolicy"] != "Never" {
		t.Fatal("kubeadm can pull mutable aliases")
	}
	if strings.Contains(string(payload), state.Credentials.OperatorToken) || strings.Contains(string(payload), state.OwnerNonce) {
		t.Fatal("public component configuration exposes credentials or private ownership")
	}
	containerd := string(guestContainerdConfig(state.Profile))
	if !strings.Contains(containerd, "SystemdCgroup = true") || !strings.Contains(containerd, "@sha256:") {
		t.Fatal("runtime is missing cgroup or immutable sandbox binding")
	}
}

func TestGuestEgressRulesMatchOnlyDeclaredDNSNames(t *testing.T) {
	domains := []string{"github.com", "*.githubusercontent.com"}
	for _, name := range []string{"github.com", "release-assets.githubusercontent.com"} {
		if !guestDomainAllowed(name, domains) {
			t.Fatal("declared download blocked", name)
		}
	}
	for _, name := range []string{"evilgithub.com", "github.com.example.invalid", "githubusercontent.com", guestLoopback()} {
		if guestDomainAllowed(name, domains) {
			t.Fatal("undeclared download allowed", name)
		}
	}
	buffer := &guestLimitedBuffer{maximum: 8}
	if _, err := buffer.Write([]byte("12345678")); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write([]byte("9")); err == nil {
		t.Fatal("command output bound ignored")
	}
}

//go:embed testdata/kube-proxy-v1.35.8.yaml
var upstreamProxyTemplate []byte

func proxyManifestFixture(t *testing.T) []byte {
	t.Helper()
	// Assemble the native context from public service-account file references.
	// No captured credential document or credential value is a repository asset.
	configuration := map[string]any{
		"apiVersion": "v1", "kind": "Config", "current-context": "default",
		"clusters": []any{map[string]any{"name": "default", "cluster": map[string]any{
			"certificate-authority": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
			"server":                "https://control-plane.example.test:6443"}}},
		"contexts": []any{map[string]any{"name": "default", "context": map[string]any{
			"cluster": "default", "namespace": "default", "user": "default"}}},
		"users": []any{map[string]any{"name": "default", "user": map[string]any{ // #nosec G101 -- The native kube-proxy fixture references a projected service-account file; no token value is embedded.
			"tokenFile": "/var/run/secrets/kubernetes.io/serviceaccount/token"}}},
	}
	contextDocument, err := yaml.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(upstreamProxyTemplate))
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	for {
		var object map[string]any
		if err := decoder.Decode(&object); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if object["kind"] == "ConfigMap" {
			object["data"].(map[string]any)["kubeconfig.conf"] = string(contextDocument)
		}
		if err := encoder.Encode(object); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestGuestPinsFullUpstreamProxyManifestBeforeFirstPod(t *testing.T) {
	upstreamProxyFixture := proxyManifestFixture(t)
	image := ImagePin{Name: "registry.k8s.io/kube-proxy:v1.35.8", Digest: "sha256:" + strings.Repeat("a", 64)}
	objects, err := guestPinnedProxyObjects(upstreamProxyFixture, image)
	if err != nil || len(objects) != 6 {
		t.Fatalf("full upstream proxy contract rejected: %v", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(upstreamProxyFixture))
	for _, actual := range objects {
		var expected map[string]any
		if err := decoder.Decode(&expected); err != nil {
			t.Fatal(err)
		}
		if expected["kind"] == "DaemonSet" {
			container := nested(apiObject(expected), "spec", "template", "spec")["containers"].([]any)[0].(map[string]any)
			container["image"] = "registry.k8s.io/kube-proxy@" + image.Digest
			container["imagePullPolicy"] = "Never"
		}
		if !reflect.DeepEqual(expected, actual) {
			t.Fatalf("unrelated upstream object content changed: %v", actual["kind"])
		}
	}
	for name, payload := range map[string][]byte{
		"changed-source-image": bytes.Replace(upstreamProxyFixture, []byte(image.Name), []byte("registry.k8s.io/kube-proxy:other"), 1),
		"changed-namespace":    bytes.Replace(upstreamProxyFixture, []byte("namespace: kube-system"), []byte("namespace: default"), 1),
		"duplicate-object":     append(append([]byte{}, upstreamProxyFixture...), []byte("\n---\napiVersion: v1\nkind: ServiceAccount\nmetadata: {name: kube-proxy, namespace: kube-system}\n")...),
		"missing-objects":      []byte("apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: kube-proxy, namespace: kube-system}\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := guestPinnedProxyObjects(payload, image); err == nil {
				t.Fatal("unsafe upstream manifest accepted")
			}
		})
	}
}
