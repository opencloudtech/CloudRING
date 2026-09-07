// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func guestTestState(t *testing.T) State {
	t.Helper()
	profile := testProfile()
	credentials, err := newCredentials(profile, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return State{APIVersion: stateSchema, Profile: profile, InstallationID: profile.InstallationID,
		ProfileSHA256: Fingerprint(profile), OwnerNonce: strings.Repeat("a", 64), Credentials: credentials}
}

func guestTestObjects(t *testing.T, state State) map[string]map[string]any {
	t.Helper()
	objects, err := guestWorkloadObjects(state)
	if err != nil {
		t.Fatal(err)
	}
	index := map[string]map[string]any{}
	for _, object := range objects {
		metadata := object["metadata"].(map[string]any)
		key := object["kind"].(string) + "/" + metadata["name"].(string)
		if index[key] != nil {
			t.Fatal("duplicate guest resource identity")
		}
		index[key] = object
	}
	return index
}

func guestTestSecret(t *testing.T, object map[string]any) map[string]string {
	t.Helper()
	result := map[string]string{}
	for key, encoded := range object["data"].(map[string]any) {
		value, err := base64.StdEncoding.DecodeString(encoded.(string))
		if err != nil {
			t.Fatal("invalid Secret encoding")
		}
		result[key] = string(value)
	}
	return result
}

func guestTestPod(object map[string]any) map[string]any {
	return object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
}

func TestGuestWorkloadsKeepAdministrativeCredentialsOutsideRuntime(t *testing.T) {
	state := guestTestState(t)
	objects := guestTestObjects(t, state)
	runtime := guestTestSecret(t, objects["Secret/cloudring-runtime"])
	migration := guestTestSecret(t, objects["Secret/cloudring-migration"])
	postgres := guestTestSecret(t, objects["Secret/postgresql-bootstrap"])
	if len(runtime) != 5 || len(migration) != 2 || len(postgres) != 4 {
		t.Fatal("guest credential scopes unexpectedly expanded")
	}
	for _, item := range []struct {
		value, role, password, certificate string
	}{
		{runtime["application-dsn"], "cloudring_app", state.Credentials.DatabaseApplicationPassword, "/run/cloudring-runtime/ca.crt"},
		{migration["owner-dsn"], "cloudring_owner", state.Credentials.DatabaseOwnerPassword, "/run/cloudring-migration/ca.crt"},
	} {
		dsn, err := url.Parse(item.value)
		if err != nil || dsn.User == nil {
			t.Fatal("invalid role DSN")
		}
		password, present := dsn.User.Password()
		if dsn.Scheme != "postgresql" || dsn.User.Username() != item.role || !present || password != item.password ||
			dsn.Host != "postgresql.cloudring-system.svc.cluster.local:5432" || dsn.Path != "/cloudring" ||
			dsn.Query().Get("sslmode") != "verify-full" || dsn.Query().Get("sslrootcert") != item.certificate || len(dsn.Query()) != 2 {
			t.Fatal("database role, hostname, TLS or secret projection is invalid")
		}
	}
	if runtime["operator-token"] != state.Credentials.OperatorToken || postgres["admin-password"] != state.Credentials.DatabaseAdminPassword ||
		runtime["tls.key"] == postgres["tls.key"] || runtime["ca.crt"] != migration["ca.crt"] {
		t.Fatal("installation credential separation changed")
	}
	for _, key := range []string{"ConfigMap/cloudring-runtime", "ConfigMap/cloudring-migration", "ConfigMap/postgresql-config", "Deployment/cloudring-runtime", "Job/cloudring-migration", "StatefulSet/postgresql"} {
		payload, err := json.Marshal(objects[key])
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{state.Credentials.OperatorToken, state.Credentials.DatabaseAdminPassword,
			state.Credentials.DatabaseOwnerPassword, state.Credentials.DatabaseApplicationPassword, state.Credentials.APIKey, state.Credentials.DatabaseKey} {
			if strings.Contains(string(payload), value) || strings.Contains(string(payload), base64.StdEncoding.EncodeToString([]byte(value))) {
				t.Fatal("credential escaped into a non-Secret resource")
			}
		}
	}
	for _, item := range []struct{ workload, allowedSecret string }{{"Deployment/cloudring-runtime", "cloudring-runtime"}, {"Job/cloudring-migration", "cloudring-migration"}} {
		count := 0
		for _, raw := range guestTestPod(objects[item.workload])["volumes"].([]any) {
			volume := raw.(map[string]any)
			if secret, ok := volume["secret"].(map[string]any); ok {
				count++
				if secret["secretName"] != item.allowedSecret {
					t.Fatal("workload can read a different database role or administrator secret")
				}
			}
		}
		if count != 1 {
			t.Fatal("workload credential projection is missing or broadened")
		}
	}
}

func TestGuestWorkloadsRetainStorageAndEnforceRestrictedPods(t *testing.T) {
	state := guestTestState(t)
	objects := guestTestObjects(t, state)
	namespace := objects["Namespace/cloudring-system"]["metadata"].(map[string]any)["labels"].(map[string]any)
	if namespace["pod-security.kubernetes.io/enforce"] != "restricted" || namespace["pod-security.kubernetes.io/enforce-version"] != "v1.35" {
		t.Fatal("guest namespace does not enforce the selected restricted Pod Security version")
	}
	pv := objects["PersistentVolume/cloudring-postgresql-data"]["spec"].(map[string]any)
	pvc := objects["PersistentVolumeClaim/postgresql-data"]["spec"].(map[string]any)
	if pv["persistentVolumeReclaimPolicy"] != "Retain" || pv["storageClassName"] != "" || pvc["storageClassName"] != "" ||
		pvc["volumeName"] != "cloudring-postgresql-data" || pv["local"].(map[string]any)["path"] != "/var/lib/cloudring-development/postgresql-data" {
		t.Fatal("database persistence can select an external provisioner or unrelated host directory")
	}
	affinityJSON, err := json.Marshal(pv["nodeAffinity"])
	if err != nil || !strings.Contains(string(affinityJSON), `"values":["`+state.InstallationID+`"]`) {
		t.Fatal("local data is not constrained to the owned guest node")
	}
	for _, key := range []string{"StatefulSet/postgresql", "Deployment/cloudring-runtime", "Job/cloudring-migration"} {
		pod := guestTestPod(objects[key])
		security := pod["securityContext"].(map[string]any)
		if pod["automountServiceAccountToken"] != false || pod["enableServiceLinks"] != false || security["runAsNonRoot"] != true ||
			security["runAsUser"].(int) <= 0 || security["runAsGroup"].(int) <= 0 || security["fsGroup"].(int) <= 0 ||
			security["seccompProfile"].(map[string]any)["type"] != "RuntimeDefault" {
			t.Fatal("guest workload acquired root, Kubernetes credentials or relaxed seccomp")
		}
		for _, field := range []string{"hostNetwork", "hostPID", "hostIPC", "initContainers", "hostAliases"} {
			if _, present := pod[field]; present {
				t.Fatal("unexpected host access or initialization container")
			}
		}
		for _, raw := range pod["containers"].([]any) {
			container := raw.(map[string]any)
			security := container["securityContext"].(map[string]any)
			if security["allowPrivilegeEscalation"] != false || security["readOnlyRootFilesystem"] != true ||
				!reflect.DeepEqual(security["capabilities"].(map[string]any)["drop"], []string{"ALL"}) || !pinnedImage(container["image"].(string)) {
				t.Fatal("container lacks restricted security or immutable image")
			}
			resources := container["resources"].(map[string]any)
			for _, section := range []string{"requests", "limits"} {
				values := resources[section].(map[string]any)
				if values["cpu"] == "" || values["memory"] == "" {
					t.Fatal("container resources are unbounded")
				}
			}
		}
		for _, raw := range pod["volumes"].([]any) {
			volume := raw.(map[string]any)
			if _, present := volume["hostPath"]; present {
				t.Fatal("restricted workload acquired a hostPath")
			}
			if secret, present := volume["secret"].(map[string]any); present && secret["defaultMode"] != 0o440 {
				t.Fatal("credential projection is not private and group-readable")
			}
		}
	}
	pg := guestTestPod(objects["StatefulSet/postgresql"])
	if pg["securityContext"].(map[string]any)["runAsUser"] != 999 || pg["securityContext"].(map[string]any)["runAsGroup"] != 999 {
		t.Fatal("PostgreSQL credentials do not match the verified image identity")
	}
	service := objects["Service/cloudring-runtime"]["spec"].(map[string]any)
	if service["type"] != "NodePort" || service["ports"].([]any)[0].(map[string]any)["nodePort"] != 30443 {
		t.Fatal("runtime service does not match the bounded guest transport")
	}
	if _, present := objects["Job/cloudring-migration"]["spec"].(map[string]any)["ttlSecondsAfterFinished"]; present {
		t.Fatal("migration acceptance evidence would disappear before restart readback")
	}
}

func TestGuestWorkloadsFailClosedBeforeRenderingUntrustedCredentials(t *testing.T) {
	baseline := guestTestState(t)
	cases := map[string]func(*State){
		"SQL injection":                func(s *State) { s.Credentials.DatabaseOwnerPassword = "'; CREATE ROLE injected SUPERUSER; --" },
		"application password newline": func(s *State) { s.Credentials.DatabaseApplicationPassword += "\n" },
		"reused administrator value":   func(s *State) { s.Credentials.DatabaseApplicationPassword = s.Credentials.DatabaseAdminPassword },
		"foreign installation":         func(s *State) { s.InstallationID = "other-installation" },
		"changed profile": func(s *State) {
			s.Profile.Network.PodCIDR = netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 29, 0, 0}), 16).String()
		},
		"invalid owner nonce":        func(s *State) { s.OwnerNonce = "unowned" },
		"missing CA":                 func(s *State) { s.Credentials.CACertificate = "" },
		"mismatched API private key": func(s *State) { s.Credentials.APIKey = s.Credentials.DatabaseKey },
		"invalid database TLS":       func(s *State) { s.Credentials.DatabaseCertificate = "invalid" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			state := baseline
			mutate(&state)
			objects, err := guestWorkloadObjects(state)
			if err == nil || objects != nil {
				t.Fatal("unsafe guest input produced deployable resources")
			}
			if strings.Contains(err.Error(), state.Credentials.DatabaseOwnerPassword) {
				t.Fatal("credential appeared in a rejection diagnostic")
			}
		})
	}
}

func TestGuestWorkloadsRenderDeterministicallyWithoutFixtureState(t *testing.T) {
	state := guestTestState(t)
	first, err := guestWorkloadObjects(state)
	if err != nil {
		t.Fatal(err)
	}
	second, err := guestWorkloadObjects(state)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("rendering regenerated credentials or changed desired state")
	}
	objects := guestTestObjects(t, state)
	sql := guestTestSecret(t, objects["Secret/postgresql-bootstrap"])["00-cloudring.sql"]
	for _, forbidden := range []string{"INSERT ", "CREATE TABLE", "cloudring_state", "products", " ON CONFLICT ", " IF NOT EXISTS "} {
		if strings.Contains(sql, forbidden) {
			t.Fatal("initialization seeded fixture/domain state or adopted unknown database state")
		}
	}
	if !strings.Contains(sql, "CREATE DATABASE cloudring OWNER cloudring_owner;") ||
		!strings.Contains(sql, "REVOKE ALL PRIVILEGES ON DATABASE cloudring FROM PUBLIC;") ||
		!strings.Contains(sql, "cloudring_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS") {
		t.Fatal("migration ownership or steady-state application privilege contract changed")
	}
	hba := objects["ConfigMap/postgresql-config"]["data"].(map[string]any)["pg_hba.conf"].(string)
	allIPv4 := netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0).String()
	if strings.Contains(hba, "trust") || !strings.Contains(hba, "hostnossl all all "+allIPv4+" reject") ||
		!strings.Contains(hba, "hostssl cloudring cloudring_owner,cloudring_app "+state.Profile.Network.PodCIDR+" scram-sha-256") {
		t.Fatal("database authentication permits cleartext, trust or unrelated networks")
	}
	for identity, object := range objects {
		metadata := object["metadata"].(map[string]any)
		if metadata["labels"].(map[string]any)[OwnerLabel] != state.InstallationID ||
			metadata["annotations"].(map[string]any)[OwnerAnnotation] != state.OwnerNonce ||
			metadata["annotations"].(map[string]any)[ProfileAnnotation] != state.ProfileSHA256 {
			t.Fatal("guest resource has no installation ownership binding")
		}
		if !strings.HasPrefix(identity, "Namespace/") && !strings.HasPrefix(identity, "PersistentVolume/") && metadata["namespace"] != "cloudring-system" {
			t.Fatal("guest workload escaped its namespace")
		}
	}
}
