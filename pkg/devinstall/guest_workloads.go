// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

const (
	guestNamespace       = "cloudring-system"
	guestDatabaseName    = "cloudring"
	guestDatabaseOwner   = "cloudring_owner"
	guestDatabaseApp     = "cloudring_app"
	guestDatabasePath    = "/var/lib/cloudring-development/postgresql-data"
	guestPostgreSQLUID   = 999
	guestPostgreSQLGID   = 999
	guestRuntimeUID      = 65532
	guestRuntimeGID      = 65532
	guestRuntimeNodePort = 30443
)

// guestWorkloadObjects only renders this installation's guest resources. Its
// output contains Secrets and must travel over the authenticated guest channel,
// never into a plan, diagnostic, public artifact or command argument.
//
// Apply prerequisites first, wait for postgresql, then run cloudring-migration
// to completion before applying the cloudring-runtime Deployment. PostgreSQL
// persists on the owned guest disk; the serving process receives no owner or
// administrator database credential and has no Kubernetes API credential.
func guestWorkloadObjects(state State) ([]map[string]any, error) {
	if Validate(state.Profile, Development) != nil || state.APIVersion != stateSchema ||
		state.InstallationID != state.Profile.InstallationID || state.ProfileSHA256 != Fingerprint(state.Profile) ||
		!hexDigest.MatchString(state.OwnerNonce) {
		return nil, ErrInvalidProfile
	}
	credentials := state.Credentials
	seen := map[string]bool{}
	for _, value := range []string{credentials.OperatorToken, credentials.DatabaseAdminPassword,
		credentials.DatabaseOwnerPassword, credentials.DatabaseApplicationPassword} {
		if !hexDigest.MatchString(value) || seen[value] {
			return nil, errors.New("development guest credentials are invalid")
		}
		seen[value] = true
	}
	for _, pair := range [][2]string{{credentials.APICertificate, credentials.APIKey},
		{credentials.DatabaseCertificate, credentials.DatabaseKey}} {
		if _, err := tls.X509KeyPair([]byte(pair[0]), []byte(pair[1])); err != nil {
			return nil, errors.New("development guest TLS identity is invalid")
		}
	}
	if credentials.CACertificate == "" {
		return nil, errors.New("development guest certificate authority is missing")
	}

	object := func(version, kind, name string, namespaced bool) map[string]any {
		metadata := map[string]any{"name": name,
			"labels":      map[string]any{OwnerLabel: state.InstallationID},
			"annotations": map[string]any{OwnerAnnotation: state.OwnerNonce, ProfileAnnotation: state.ProfileSHA256}}
		if namespaced {
			metadata["namespace"] = guestNamespace
		}
		return map[string]any{"apiVersion": version, "kind": kind, "metadata": metadata}
	}
	renderSecret := func(name string, values map[string]string) map[string]any {
		result := object("v1", "Secret", name, true)
		data := map[string]any{}
		for key, value := range values {
			data[key] = base64.StdEncoding.EncodeToString([]byte(value))
		}
		result["type"], result["immutable"], result["data"] = "Opaque", true, data
		return result
	}
	configMap := func(name string, values map[string]any) map[string]any {
		result := object("v1", "ConfigMap", name, true)
		result["immutable"], result["data"] = true, values
		return result
	}
	configuration := func(kind, dsnPath string) map[string]any {
		return map[string]any{"apiVersion": "cloudring.org/v1alpha1", "kind": kind, "profile": Development,
			"installationID": state.InstallationID, "databaseDSNFile": dsnPath,
			"migrationOwnerRole": guestDatabaseOwner, "applicationRole": guestDatabaseApp}
	}
	runtimeConfig := configuration("CloudRINGDevelopmentRuntime", "/run/cloudring-runtime/application-dsn")
	runtimeConfig["publicOrigin"], runtimeConfig["listenAddress"] = state.Profile.Network.PublicOrigin, ":8443"
	runtimeConfig["tlsCertificateFile"], runtimeConfig["tlsPrivateKeyFile"] = "/run/cloudring-runtime/tls.crt", "/run/cloudring-runtime/tls.key"
	runtimeConfig["developmentOperatorTokenFile"] = "/run/cloudring-runtime/operator-token"
	migrationConfig := configuration("CloudRINGDevelopmentMigration", "/run/cloudring-migration/owner-dsn")
	runtimeJSON, err := json.Marshal(runtimeConfig)
	if err != nil {
		return nil, errors.New("encode development runtime configuration")
	}
	migrationJSON, err := json.Marshal(migrationConfig)
	if err != nil {
		return nil, errors.New("encode development migration configuration")
	}

	namespace := object("v1", "Namespace", guestNamespace, false)
	namespaceLabels := namespace["metadata"].(map[string]any)["labels"].(map[string]any)
	for _, level := range []string{"enforce", "audit", "warn"} {
		namespaceLabels["pod-security.kubernetes.io/"+level] = "restricted"
		namespaceLabels["pod-security.kubernetes.io/"+level+"-version"] = "v1.35"
	}
	pv := object("v1", "PersistentVolume", "cloudring-postgresql-data", false)
	pv["spec"] = map[string]any{"capacity": map[string]any{"storage": "32Gi"}, "volumeMode": "Filesystem",
		"accessModes": []string{"ReadWriteOnce"}, "persistentVolumeReclaimPolicy": "Retain", "storageClassName": "",
		"claimRef": map[string]any{"namespace": guestNamespace, "name": "postgresql-data"},
		"local":    map[string]any{"path": guestDatabasePath},
		"nodeAffinity": map[string]any{"required": map[string]any{"nodeSelectorTerms": []any{map[string]any{
			"matchExpressions": []any{map[string]any{"key": "kubernetes.io/hostname", "operator": "In", "values": []string{state.InstallationID}}}}}}}}
	pvc := object("v1", "PersistentVolumeClaim", "postgresql-data", true)
	pvc["spec"] = map[string]any{"accessModes": []string{"ReadWriteOnce"}, "volumeMode": "Filesystem", "storageClassName": "",
		"volumeName": "cloudring-postgresql-data", "resources": map[string]any{"requests": map[string]any{"storage": "32Gi"}}}

	postgresService := object("v1", "Service", "postgresql", true)
	postgresService["spec"] = map[string]any{"type": "ClusterIP", "selector": guestWorkloadSelector("postgresql"),
		"ports": []any{map[string]any{"name": "postgresql", "port": 5432, "targetPort": "postgresql", "protocol": "TCP"}}}
	runtimeService := object("v1", "Service", "cloudring-runtime", true)
	// The bootstrap pins kube-proxy's nodePortAddresses to the IPv4 loopback range and
	// enables localhostNodePorts in iptables mode. The parent VM exposes only
	// SSH; the client reaches this port inside the authenticated SSH channel.
	runtimeService["spec"] = map[string]any{"type": "NodePort", "selector": guestWorkloadSelector("cloudring-runtime"),
		"externalTrafficPolicy": "Cluster", "ports": []any{map[string]any{"name": "https", "port": 443,
			"targetPort": "https", "nodePort": guestRuntimeNodePort, "protocol": "TCP"}}}

	postgres := object("apps/v1", "StatefulSet", "postgresql", true)
	postgresPod := guestWorkloadPod(state, "postgresql", guestPostgreSQLUID, guestPostgreSQLGID)
	postgresPod["containers"] = []any{map[string]any{"name": "postgresql", "image": state.Profile.Artifacts.PostgreSQLImage,
		"imagePullPolicy": "IfNotPresent", "securityContext": guestContainerSecurity(),
		"args": []string{"postgres", "-c", "ssl=on", "-c", "ssl_min_protocol_version=TLSv1.3",
			"-c", "ssl_cert_file=/run/cloudring-postgresql/tls.crt", "-c", "ssl_key_file=/run/cloudring-postgresql/tls.key",
			"-c", "hba_file=/etc/cloudring-postgresql/pg_hba.conf", "-c", "password_encryption=scram-sha-256",
			"-c", "max_connections=32", "-c", "shared_buffers=128MB"},
		"env": []any{map[string]any{"name": "POSTGRES_USER", "value": "postgres"}, map[string]any{"name": "POSTGRES_DB", "value": "postgres"},
			map[string]any{"name": "POSTGRES_PASSWORD_FILE", "value": "/run/cloudring-postgresql/admin-password"},
			map[string]any{"name": "POSTGRES_INITDB_ARGS", "value": "--auth-local=peer --auth-host=scram-sha-256 --data-checksums"},
			map[string]any{"name": "PGDATA", "value": "/var/lib/postgresql/18/docker"}},
		"ports":        []any{map[string]any{"name": "postgresql", "containerPort": 5432}},
		"resources":    guestResources("250m", "512Mi", "1000m", "1Gi"),
		"startupProbe": guestPostgreSQLProbe(60, 5), "readinessProbe": guestPostgreSQLProbe(3, 5),
		"livenessProbe": guestPostgreSQLProbe(6, 10),
		"volumeMounts": []any{guestMount("data", "/var/lib/postgresql", false), guestMount("postgresql-secrets", "/run/cloudring-postgresql", true),
			guestMount("postgresql-init", "/docker-entrypoint-initdb.d", true), guestMount("postgresql-config", "/etc/cloudring-postgresql", true),
			guestMount("socket", "/var/run/postgresql", false), guestMount("tmp", "/tmp", false)}}}
	postgresPod["volumes"] = []any{map[string]any{"name": "data", "persistentVolumeClaim": map[string]any{"claimName": "postgresql-data"}},
		guestSecretVolume("postgresql-secrets", "postgresql-bootstrap", []string{"admin-password", "tls.crt", "tls.key"}),
		guestSecretVolume("postgresql-init", "postgresql-bootstrap", []string{"00-cloudring.sql"}),
		guestConfigVolume("postgresql-config", "postgresql-config"), guestEmptyVolume("socket", "64Mi"), guestEmptyVolume("tmp", "64Mi")}
	postgresPod["terminationGracePeriodSeconds"] = 90
	postgres["spec"] = map[string]any{"serviceName": "postgresql", "replicas": 1,
		"selector": map[string]any{"matchLabels": guestWorkloadSelector("postgresql")},
		"template": map[string]any{"metadata": guestPodMetadata(state, "postgresql"), "spec": postgresPod}}

	runtimePod := guestWorkloadPod(state, "cloudring-runtime", guestRuntimeUID, guestRuntimeGID)
	runtimePod["containers"] = []any{map[string]any{"name": "runtime", "image": state.Profile.Artifacts.RuntimeImage,
		"imagePullPolicy": "IfNotPresent", "args": []string{"serve", "--config", "/etc/cloudring/runtime.json"},
		"securityContext": guestContainerSecurity(), "resources": guestResources("100m", "128Mi", "1000m", "512Mi"),
		"ports":        []any{map[string]any{"name": "https", "containerPort": 8443}},
		"startupProbe": guestRuntimeProbe("/healthz/ready", 60, 5), "readinessProbe": guestRuntimeProbe("/healthz/ready", 3, 5),
		"livenessProbe": guestRuntimeProbe("/healthz/live", 3, 10),
		"volumeMounts":  []any{guestMount("runtime-config", "/etc/cloudring", true), guestMount("runtime-secrets", "/run/cloudring-runtime", true)}}}
	runtimePod["volumes"] = []any{guestConfigVolume("runtime-config", "cloudring-runtime"),
		guestSecretVolume("runtime-secrets", "cloudring-runtime", []string{"application-dsn", "operator-token", "tls.crt", "tls.key", "ca.crt"})}
	runtime := object("apps/v1", "Deployment", "cloudring-runtime", true)
	runtime["spec"] = map[string]any{"replicas": 1, "revisionHistoryLimit": 1, "strategy": map[string]any{"type": "Recreate"},
		"selector": map[string]any{"matchLabels": guestWorkloadSelector("cloudring-runtime")},
		"template": map[string]any{"metadata": guestPodMetadata(state, "cloudring-runtime"), "spec": runtimePod}}

	migrationPod := guestWorkloadPod(state, "cloudring-migration", guestRuntimeUID, guestRuntimeGID)
	migrationPod["restartPolicy"] = "Never"
	migrationPod["containers"] = []any{map[string]any{"name": "migration", "image": state.Profile.Artifacts.RuntimeImage,
		"imagePullPolicy": "IfNotPresent", "args": []string{"migrate", "--config", "/etc/cloudring/migration.json"},
		"securityContext": guestContainerSecurity(), "resources": guestResources("100m", "128Mi", "1000m", "512Mi"),
		"volumeMounts": []any{guestMount("migration-config", "/etc/cloudring", true), guestMount("migration-secrets", "/run/cloudring-migration", true)}}}
	migrationPod["volumes"] = []any{guestConfigVolume("migration-config", "cloudring-migration"),
		guestSecretVolume("migration-secrets", "cloudring-migration", []string{"owner-dsn", "ca.crt"})}
	migration := object("batch/v1", "Job", "cloudring-migration", true)
	// Preserve the completed Job for restart-safe readback; the owned guest's
	// lifecycle removes it. Automatic retries cannot hide an initialization error.
	migration["spec"] = map[string]any{"backoffLimit": 0, "activeDeadlineSeconds": 180,
		"template": map[string]any{"metadata": guestPodMetadata(state, "cloudring-migration"), "spec": migrationPod}}

	objects := []map[string]any{namespace, pv, pvc,
		renderSecret("postgresql-bootstrap", map[string]string{"admin-password": credentials.DatabaseAdminPassword,
			"00-cloudring.sql": guestDatabaseInitialization(credentials), "tls.crt": credentials.DatabaseCertificate, "tls.key": credentials.DatabaseKey}),
		renderSecret("cloudring-runtime", map[string]string{"application-dsn": guestDatabaseDSN(guestDatabaseApp, credentials.DatabaseApplicationPassword, "/run/cloudring-runtime/ca.crt"),
			"operator-token": credentials.OperatorToken, "tls.crt": credentials.APICertificate, "tls.key": credentials.APIKey, "ca.crt": credentials.CACertificate}),
		renderSecret("cloudring-migration", map[string]string{"owner-dsn": guestDatabaseDSN(guestDatabaseOwner, credentials.DatabaseOwnerPassword, "/run/cloudring-migration/ca.crt"), "ca.crt": credentials.CACertificate}),
		configMap("postgresql-config", map[string]any{"pg_hba.conf": guestDatabaseHBA(state.Profile.Network.PodCIDR)}),
		configMap("cloudring-runtime", map[string]any{"runtime.json": string(runtimeJSON)}),
		configMap("cloudring-migration", map[string]any{"migration.json": string(migrationJSON)}),
		postgresService, runtimeService}
	objects = append(objects, guestWorkloadNetworkPolicies(state, object)...)
	return append(objects, postgres, migration, runtime), nil
}

func guestDatabaseInitialization(credentials Credentials) string {
	// All identifiers are constants and both interpolated passwords have passed
	// the exact lowercase-hex validator before this function is called.
	return fmt.Sprintf(`CREATE ROLE cloudring_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '%s';
CREATE ROLE cloudring_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS PASSWORD '%s';
CREATE DATABASE cloudring OWNER cloudring_owner;
REVOKE ALL PRIVILEGES ON DATABASE cloudring FROM PUBLIC;
GRANT CONNECT ON DATABASE cloudring TO cloudring_app;
\connect cloudring
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;
`, credentials.DatabaseOwnerPassword, credentials.DatabaseApplicationPassword)
}

func guestDatabaseHBA(podCIDR string) string {
	allIPv4 := netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0).String()
	allIPv6 := netip.PrefixFrom(netip.IPv6Unspecified(), 0).String()
	return "local all postgres peer\n" +
		"hostnossl all all " + allIPv4 + " reject\n" +
		"hostssl cloudring cloudring_owner,cloudring_app " + podCIDR + " scram-sha-256\n" +
		"host all all " + allIPv4 + " reject\n" +
		"host all all " + allIPv6 + " reject\n"
}

func guestDatabaseDSN(role, password, caFile string) string {
	host := strings.Join([]string{"postgresql", guestNamespace, "svc", "cluster", "local"}, ".")
	location := &url.URL{Scheme: "postgresql", User: url.UserPassword(role, password),
		Host: net.JoinHostPort(host, "5432"), Path: "/" + guestDatabaseName}
	query := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {caFile}}
	location.RawQuery = query.Encode()
	return location.String()
}

func guestWorkloadSelector(name string) map[string]any {
	return map[string]any{"app.kubernetes.io/name": name}
}

func guestPodMetadata(state State, name string) map[string]any {
	labels := guestWorkloadSelector(name)
	labels[OwnerLabel] = state.InstallationID
	return map[string]any{"labels": labels,
		"annotations": map[string]any{OwnerAnnotation: state.OwnerNonce, ProfileAnnotation: state.ProfileSHA256}}
}

func guestWorkloadPod(state State, _ string, uid, gid int) map[string]any {
	return map[string]any{"automountServiceAccountToken": false, "enableServiceLinks": false,
		"nodeSelector": map[string]any{"kubernetes.io/hostname": state.InstallationID},
		"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": uid, "runAsGroup": gid, "fsGroup": gid,
			"fsGroupChangePolicy": "OnRootMismatch", "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		"terminationGracePeriodSeconds": 30}
}

func guestContainerSecurity() map[string]any {
	return map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
		"capabilities": map[string]any{"drop": []string{"ALL"}}}
}

func guestResources(cpuRequest, memoryRequest, cpuLimit, memoryLimit string) map[string]any {
	return map[string]any{"requests": map[string]any{"cpu": cpuRequest, "memory": memoryRequest},
		"limits": map[string]any{"cpu": cpuLimit, "memory": memoryLimit}}
}

func guestMount(name, path string, readOnly bool) map[string]any {
	return map[string]any{"name": name, "mountPath": path, "readOnly": readOnly}
}

func guestSecretVolume(name, secret string, keys []string) map[string]any {
	items := make([]any, 0, len(keys))
	for _, key := range keys {
		items = append(items, map[string]any{"key": key, "path": key})
	}
	volumeSource := map[string]any{"secretName": secret, "defaultMode": 0o440, "items": items}
	result := map[string]any{"name": name}
	result["secret"] = volumeSource
	return result
}

func guestConfigVolume(name, configMap string) map[string]any {
	return map[string]any{"name": name, "configMap": map[string]any{"name": configMap, "defaultMode": 0o444}}
}

func guestEmptyVolume(name, maximum string) map[string]any {
	return map[string]any{"name": name, "emptyDir": map[string]any{"sizeLimit": maximum}}
}

func guestPostgreSQLProbe(failures, period int) map[string]any {
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1}).String()
	return map[string]any{"exec": map[string]any{"command": []string{"pg_isready", "-h", loopback, "-p", "5432", "-U", "postgres", "-d", "postgres"}},
		"timeoutSeconds": 3, "periodSeconds": period, "failureThreshold": failures}
}

func guestRuntimeProbe(path string, failures, period int) map[string]any {
	return map[string]any{"httpGet": map[string]any{"path": path, "port": "https", "scheme": "HTTPS"},
		"timeoutSeconds": 3, "periodSeconds": period, "failureThreshold": failures}
}

func guestWorkloadNetworkPolicies(state State, object func(string, string, string, bool) map[string]any) []map[string]any {
	policy := func(name string, spec map[string]any) map[string]any {
		result := object("networking.k8s.io/v1", "NetworkPolicy", name, true)
		result["spec"] = spec
		return result
	}
	port := func(number int, protocol string) map[string]any {
		return map[string]any{"port": number, "protocol": protocol}
	}
	databasePeer := map[string]any{"podSelector": map[string]any{"matchLabels": guestWorkloadSelector("postgresql")}}
	clients := map[string]any{"matchExpressions": []any{map[string]any{"key": "app.kubernetes.io/name", "operator": "In",
		"values": []string{"cloudring-runtime", "cloudring-migration"}}}}
	dnsPeer := map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": "kube-system"}},
		"podSelector": map[string]any{"matchLabels": map[string]any{"k8s-app": "kube-dns"}}}
	return []map[string]any{
		policy("default-deny", map[string]any{"podSelector": map[string]any{}, "policyTypes": []string{"Ingress", "Egress"}}),
		policy("postgresql-clients", map[string]any{"podSelector": map[string]any{"matchLabels": guestWorkloadSelector("postgresql")},
			"policyTypes": []string{"Ingress"}, "ingress": []any{map[string]any{"from": []any{map[string]any{"podSelector": clients}}, "ports": []any{port(5432, "TCP")}}}}),
		policy("runtime-database-and-dns", map[string]any{"podSelector": clients, "policyTypes": []string{"Egress"},
			"egress": []any{map[string]any{"to": []any{databasePeer}, "ports": []any{port(5432, "TCP")}},
				map[string]any{"to": []any{dnsPeer}, "ports": []any{port(53, "UDP"), port(53, "TCP")}}}}),
		policy("runtime-guest-access", map[string]any{"podSelector": map[string]any{"matchLabels": guestWorkloadSelector("cloudring-runtime")},
			"policyTypes": []string{"Ingress"}, "ingress": []any{map[string]any{"from": []any{map[string]any{"ipBlock": map[string]any{"cidr": state.Profile.Network.GuestCIDR}}},
				"ports": []any{port(8443, "TCP")}}}}),
	}
}
