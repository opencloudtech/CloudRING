// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func guestImage(bom BOM, role string) ImagePin {
	for _, image := range bom.KubernetesImages {
		name := strings.SplitN(image.Name, ":", 2)[0]
		if strings.TrimPrefix(name, "registry.k8s.io/") == role || role == "coredns/coredns" && name == "docker.io/coredns/coredns" {
			return image
		}
	}
	return ImagePin{}
}

func guestContainerdConfig(profile Profile) []byte {
	pause := guestImage(profile.Artifacts, "pause")
	return []byte("version = 3\nroot = '/var/lib/containerd'\nstate = '/run/containerd'\n" +
		"[grpc]\n  address = '/run/containerd/containerd.sock'\n" +
		"[plugins.'io.containerd.cri.v1.images'.pinned_images]\n  sandbox = '" + strings.SplitN(pause.Name, ":", 2)[0] + "@" + pause.Digest + "'\n" +
		"[plugins.'io.containerd.cri.v1.runtime'.containerd]\n  default_runtime_name = 'runc'\n" +
		"[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]\n  runtime_type = 'io.containerd.runc.v2'\n" +
		"[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]\n  SystemdCgroup = true\n  BinaryName = '" + guestDirectory + "/bin/runc'\n" +
		"[plugins.'io.containerd.cri.v1.runtime'.cni]\n  bin_dirs = ['" + guestDirectory + "/cni/bin']\n  conf_dir = '/etc/cni/net.d'\n")
}

func (bootstrap *guestBootstrap) configureHost(ctx context.Context) error {
	for _, name := range []string{"overlay", "br_netfilter"} {
		if err := bootstrap.run(ctx, 30*time.Second, "/usr/sbin/modprobe", nil, name); err != nil {
			return err
		}
	}
	if err := bootstrap.run(ctx, 30*time.Second, "/usr/sbin/swapoff", nil, "--all"); err != nil {
		return err
	}
	configuration := map[string][]byte{
		"etc/modules-load.d/cloudring-development.conf": []byte("overlay\nbr_netfilter\n"),
		"etc/sysctl.d/90-cloudring-development.conf":    []byte("net.ipv4.ip_forward=1\nnet.bridge.bridge-nf-call-iptables=1\n"),
		"etc/systemd/system/containerd.service":         []byte("[Unit]\nDescription=CloudRING development container runtime\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=notify\nEnvironment=PATH=" + guestDirectory + "/bin:/usr/sbin:/usr/bin:/sbin:/bin\nExecStart=" + guestDirectory + "/bin/containerd --config " + guestDirectory + "/containerd.toml\nDelegate=yes\nKillMode=process\nRestart=always\nRestartSec=5\nLimitNOFILE=1048576\nLimitNPROC=infinity\nLimitCORE=infinity\nTasksMax=infinity\nOOMScoreAdjust=-999\n[Install]\nWantedBy=multi-user.target\n"),
		"etc/systemd/system/kubelet.service":            []byte("[Unit]\nDescription=CloudRING development kubelet\nAfter=network-online.target containerd.service\nWants=network-online.target\nRequires=containerd.service\n[Service]\nEnvironment=PATH=" + guestDirectory + "/bin:/usr/sbin:/usr/bin:/sbin:/bin\nEnvironment=\"KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf\"\nEnvironment=\"KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml\"\nEnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env\nExecStart=" + guestDirectory + "/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS\nRestart=always\nStartLimitInterval=0\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n"),
	}
	// These standard paths are changed only after the VM firmware guard. An
	// existing foreign unit is not adopted on the first bootstrap invocation.
	if err := guestWrite(bootstrap.root, "containerd.toml", guestContainerdConfig(bootstrap.state.Profile), 0o600); err != nil {
		return err
	}
	system, err := os.OpenRoot("/")
	if err != nil {
		return errors.New("open owned guest filesystem")
	}
	defer system.Close()
	for name, payload := range configuration {
		if !containsGuestPhase(bootstrap, "host-config") {
			if existing, err := system.ReadFile(name); err == nil && string(existing) != string(payload) {
				return errors.New("guest already contains a foreign service configuration")
			}
		}
		if err := guestWrite(system, name, payload, 0o600); err != nil {
			return err
		}
	}
	if err := bootstrap.run(ctx, 30*time.Second, "/usr/sbin/sysctl", nil, "--load=/etc/sysctl.d/90-cloudring-development.conf"); err != nil {
		return err
	}
	if err := bootstrap.phase(ctx, "host-config", func(context.Context) error { return nil }); err != nil {
		return err
	}
	if err := bootstrap.run(ctx, 30*time.Second, "/usr/bin/systemctl", nil, "daemon-reload"); err != nil {
		return err
	}
	if err := bootstrap.run(ctx, 30*time.Second, "/usr/bin/systemctl", nil, "enable", "--now", "containerd.service"); err != nil {
		return err
	}
	if err := bootstrap.run(ctx, 30*time.Second, "/usr/bin/systemctl", nil, "enable", "kubelet.service"); err != nil {
		return err
	}
	return bootstrap.run(ctx, time.Minute, guestDirectory+"/bin/crictl", nil, "--runtime-endpoint=unix:///run/containerd/containerd.sock", "info")
}

func containsGuestPhase(bootstrap *guestBootstrap, name string) bool {
	for _, phase := range bootstrap.journal.Completed {
		if phase == name {
			return true
		}
	}
	return false
}

func guestKubeadmConfig(state State) ([]byte, error) {
	profile := state.Profile
	etcd := guestImage(profile.Artifacts, "etcd")
	dns := guestImage(profile.Artifacts, "coredns/coredns")
	dnsName, dnsTag, _ := strings.Cut(dns.Name, ":")
	_, etcdTag, _ := strings.Cut(etcd.Name, ":")
	documents := []map[string]any{
		{"apiVersion": "kubeadm.k8s.io/v1beta4", "kind": "InitConfiguration",
			"localAPIEndpoint": map[string]any{"advertiseAddress": guestAddress(profile).String(), "bindPort": 6443},
			"nodeRegistration": map[string]any{"name": state.InstallationID, "criSocket": "unix:///run/containerd/containerd.sock", "taints": []any{}, "imagePullPolicy": "Never"},
			"patches":          map[string]any{"directory": guestDirectory + "/kubeadm-patches"},
			"timeouts":         map[string]any{"controlPlaneComponentHealthCheck": "5m0s", "kubeletHealthCheck": "3m0s", "kubernetesAPICall": "1m0s"}},
		{"apiVersion": "kubeadm.k8s.io/v1beta4", "kind": "ClusterConfiguration", "clusterName": "cloudring-dev-" + state.InstallationID,
			"kubernetesVersion": profile.Artifacts.Kubeadm.Version,
			"networking":        map[string]any{"podSubnet": profile.Network.PodCIDR, "serviceSubnet": profile.Network.ServiceCIDR, "dnsDomain": "cluster.local"},
			"etcd":              map[string]any{"local": map[string]any{"imageTag": etcdTag}},
			"dns":               map[string]any{"imageRepository": strings.TrimSuffix(dnsName, "/coredns"), "imageTag": dnsTag}},
		{"apiVersion": "kubelet.config.k8s.io/v1beta1", "kind": "KubeletConfiguration", "cgroupDriver": "systemd", "failSwapOn": true,
			"rotateCertificates": true, "serverTLSBootstrap": false, "protectKernelDefaults": false},
		{"apiVersion": "kubeproxy.config.k8s.io/v1alpha1", "kind": "KubeProxyConfiguration", "mode": "iptables", "nodePortAddresses": []string{ipv4Prefix([4]byte{127}, 8)},
			"iptables": map[string]any{"localhostNodePorts": true}, "metricsBindAddress": net.JoinHostPort(guestLoopback(), "10249")},
	}
	var payload []byte
	for _, document := range documents {
		encoded, err := yaml.Marshal(document)
		if err != nil {
			return nil, errors.New("encode guest Kubernetes configuration")
		}
		if len(payload) > 0 {
			payload = append(payload, []byte("---\n")...)
		}
		payload = append(payload, encoded...)
	}
	return payload, nil
}

func (bootstrap *guestBootstrap) installKubernetes(ctx context.Context) error {
	if err := guestMkdir(bootstrap.root, "kubeadm-patches"); err != nil {
		return err
	}
	for _, role := range []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd"} {
		image := guestImage(bootstrap.state.Profile.Artifacts, role)
		patch := map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": role, "image": strings.SplitN(image.Name, ":", 2)[0] + "@" + image.Digest, "imagePullPolicy": "Never"}}}}
		payload, err := json.Marshal(patch)
		if err != nil {
			return errors.New("encode immutable Kubernetes image patch")
		}
		if err := guestWrite(bootstrap.root, "kubeadm-patches/"+role+"+strategic.json", payload, 0o600); err != nil {
			return err
		}
	}
	dns := guestImage(bootstrap.state.Profile.Artifacts, "coredns/coredns")
	dnsContainer := map[string]any{"name": "coredns", "image": strings.SplitN(dns.Name, ":", 2)[0] + "@" + dns.Digest, "imagePullPolicy": "Never"}
	dnsPatch := map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{dnsContainer}}}}}
	dnsPayload, err := json.Marshal(dnsPatch)
	if err != nil {
		return errors.New("encode immutable CoreDNS image patch")
	}
	if err := guestWrite(bootstrap.root, "kubeadm-patches/corednsdeployment+strategic.json", dnsPayload, 0o600); err != nil {
		return err
	}
	payload, err := guestKubeadmConfig(bootstrap.state)
	if err != nil {
		return err
	}
	if err := guestWrite(bootstrap.root, "kubeadm.yaml", payload, 0o600); err != nil {
		return err
	}
	for _, image := range bootstrap.state.Profile.Artifacts.KubernetesImages {
		if err := bootstrap.ensureImage(ctx, image); err != nil {
			return err
		}
	}
	// kubeadm's individual phases resume interrupted initialization without
	// resetting etcd or replacing the guest. Each success is journaled before
	// the next phase; certificate phases reuse their already-created keys.
	phases := []string{"preflight", "certs all", "kubeconfig all", "etcd local", "control-plane all", "kubelet-start", "wait-control-plane", "upload-config all", "mark-control-plane", "bootstrap-token", "kubelet-finalize all", "addon coredns"}
	for _, phase := range phases {
		phase := phase
		if err := bootstrap.phase(ctx, "kubeadm-"+phase, func(ctx context.Context) error {
			if phase == "wait-control-plane" {
				return bootstrap.waitKubernetes(ctx)
			}
			arguments := append([]string{"init", "phase"}, strings.Fields(phase)...)
			arguments = append(arguments, "--config", guestDirectory+"/kubeadm.yaml")
			return bootstrap.run(ctx, 8*time.Minute, guestDirectory+"/bin/kubeadm", nil, arguments...)
		}); err != nil {
			return err
		}
	}
	proxyManifest, err := bootstrap.capture(ctx, time.Minute, guestDirectory+"/bin/kubeadm", "init", "phase", "addon", "kube-proxy", "--config", guestDirectory+"/kubeadm.yaml", "--print-manifest")
	if err != nil {
		return err
	}
	proxyObjects, err := guestPinnedProxyObjects(proxyManifest, guestImage(bootstrap.state.Profile.Artifacts, "kube-proxy"))
	if err != nil {
		return err
	}
	for _, object := range proxyObjects {
		if err := bootstrap.apply(ctx, object); err != nil {
			return err
		}
	}
	return bootstrap.run(ctx, time.Minute, guestDirectory+"/bin/kubectl", nil, "get", "--raw=/readyz")
}

func (bootstrap *guestBootstrap) waitKubernetes(ctx context.Context) error {
	// Unlike the other v1.35 kubeadm phases, wait-control-plane does not
	// accept --config. Probe the actual generated admin kubeconfig instead of
	// accidentally selecting kubeadm's default address and configuration.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		if bootstrap.run(ctx, 15*time.Second, guestDirectory+"/bin/kubectl", nil, "--kubeconfig=/etc/kubernetes/admin.conf", "--request-timeout=10s", "get", "--raw=/readyz") == nil {
			return nil
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("owned guest Kubernetes API did not become ready")
		case <-timer.C:
		}
	}
}

// Upstream kubeadm does not support DaemonSet image patches. Its print-only
// path emits the native RBAC/configuration without creating resources, so the
// immutable image and Never policy can be applied before the first Pod runs.
func guestPinnedProxyObjects(payload []byte, image ImagePin) ([]map[string]any, error) {
	if len(payload) > 2<<20 || image.Name == "" || !strings.HasPrefix(image.Digest, "sha256:") || !hexDigest.MatchString(strings.TrimPrefix(image.Digest, "sha256:")) {
		return nil, errors.New("guest proxy manifest or image is invalid")
	}
	expected := map[string]string{"ServiceAccount": "kube-proxy", "ClusterRoleBinding": "kubeadm:node-proxier", "Role": "kube-proxy", "RoleBinding": "kube-proxy", "ConfigMap": "kube-proxy", "DaemonSet": "kube-proxy"}
	seen := map[string]bool{}
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	objects := []map[string]any{}
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil || !plainYAML(&node, 0) {
			return nil, errors.New("guest proxy manifest is ambiguous")
		}
		var object map[string]any
		if node.Decode(&object) != nil {
			return nil, errors.New("decode guest proxy object")
		}
		if len(object) == 0 {
			continue
		}
		kind, _ := object["kind"].(string)
		metadata, _ := object["metadata"].(map[string]any)
		if expected[kind] == "" || seen[kind] || metadata["name"] != expected[kind] || kind != "ClusterRoleBinding" && metadata["namespace"] != "kube-system" {
			return nil, errors.New("guest proxy object scope differs from upstream contract")
		}
		seen[kind] = true
		if kind == "DaemonSet" {
			specification, _ := object["spec"].(map[string]any)
			template, _ := specification["template"].(map[string]any)
			pod, _ := template["spec"].(map[string]any)
			containers, _ := pod["containers"].([]any)
			if len(containers) != 1 {
				return nil, errors.New("guest proxy has unexpected containers")
			}
			container, _ := containers[0].(map[string]any)
			if container["name"] != "kube-proxy" || container["image"] != image.Name {
				return nil, errors.New("guest proxy source image differs from pinned profile")
			}
			container["image"] = strings.SplitN(image.Name, ":", 2)[0] + "@" + image.Digest
			container["imagePullPolicy"] = "Never"
		}
		objects = append(objects, object)
	}
	if len(seen) != len(expected) {
		return nil, errors.New("guest proxy manifest is incomplete")
	}
	return objects, nil
}

func guestAliasPresent(inventory []byte, image ImagePin) (bool, error) {
	for _, line := range strings.Split(string(inventory), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == image.Name {
			if len(fields) < 3 || fields[2] != image.Digest {
				return false, errors.New("guest image alias was rebound to another digest")
			}
			return true, nil
		}
	}
	return false, nil
}

func (bootstrap *guestBootstrap) ensureImage(ctx context.Context, image ImagePin) error {
	readAlias := func() (bool, error) {
		inventory, err := bootstrap.capture(ctx, time.Minute, guestDirectory+"/bin/ctr", "--namespace", "k8s.io", "images", "list")
		if err != nil {
			return false, err
		}
		return guestAliasPresent(inventory, image)
	}
	present, err := readAlias()
	if err != nil {
		return err
	}
	if present {
		return nil
	}
	pinned := strings.SplitN(image.Name, ":", 2)[0] + "@" + image.Digest
	if err := bootstrap.run(ctx, 8*time.Minute, guestDirectory+"/bin/ctr", nil, "--namespace", "k8s.io", "images", "pull", "--platform", "linux/amd64", pinned); err != nil {
		return err
	}
	if err := bootstrap.run(ctx, time.Minute, guestDirectory+"/bin/ctr", nil, "--namespace", "k8s.io", "images", "tag", pinned, image.Name); err != nil {
		present, readErr := readAlias()
		if readErr != nil {
			return readErr
		}
		if !present {
			return err
		}
	}
	present, err = readAlias()
	if err != nil {
		return err
	}
	if !present {
		return errors.New("guest image alias is missing after import")
	}
	return nil
}

func guestCiliumValues(profile Profile) map[string]any {
	image, digest, _ := strings.Cut(profile.Artifacts.CiliumImage, "@")
	operator, operatorDigest, _ := strings.Cut(profile.Artifacts.CiliumOperatorImage, "@")
	return map[string]any{
		"image":                map[string]any{"repository": image, "digest": digest, "useDigest": true},
		"operator":             map[string]any{"replicas": 1, "image": map[string]any{"repository": strings.TrimSuffix(operator, "-generic"), "genericDigest": operatorDigest, "useDigest": true}},
		"kubeProxyReplacement": false, "routingMode": "tunnel", "tunnelProtocol": "vxlan",
		"ipam":   map[string]any{"mode": "kubernetes"},
		"cni":    map[string]any{"binPath": guestDirectory + "/cni/bin", "confPath": "/etc/cni/net.d"},
		"hubble": map[string]any{"enabled": false}, "prometheus": map[string]any{"enabled": false},
		"envoy": map[string]any{"enabled": false}, "l7Proxy": false,
	}
}

func (bootstrap *guestBootstrap) installNetwork(ctx context.Context) error {
	payload, err := yaml.Marshal(guestCiliumValues(bootstrap.state.Profile))
	if err != nil {
		return errors.New("encode guest Cilium configuration")
	}
	if err := guestWrite(bootstrap.root, "cilium-values.yaml", payload, 0o600); err != nil {
		return err
	}
	// Render the exact upstream chart, then reconcile its objects. Interrupted
	// apply is resumable without a Helm pending-install state or release reset.
	manifests, err := bootstrap.capture(ctx, time.Minute, guestDirectory+"/bin/helm", "template", "cilium", guestDirectory+"/downloads/"+bootstrap.state.Profile.Artifacts.CiliumChart.SHA256,
		"--namespace", "kube-system", "--values", guestDirectory+"/cilium-values.yaml", "--include-crds", "--skip-tests", "--kube-version", bootstrap.state.Profile.Artifacts.Kubeadm.Version)
	if err != nil {
		return err
	}
	if err := bootstrap.run(ctx, 2*time.Minute, guestDirectory+"/bin/kubectl", manifests, "apply", "--server-side", "--field-manager=cloudring-development", "--filename=-"); err != nil {
		return err
	}
	if err := bootstrap.run(ctx, 5*time.Minute, guestDirectory+"/bin/kubectl", nil, "--namespace", "kube-system", "rollout", "status", "daemonset/cilium", "--timeout=240s"); err != nil {
		return err
	}
	if err := bootstrap.run(ctx, 5*time.Minute, guestDirectory+"/bin/kubectl", nil, "--namespace", "kube-system", "rollout", "status", "deployment/cilium-operator", "--timeout=240s"); err != nil {
		return err
	}
	return bootstrap.run(ctx, 5*time.Minute, guestDirectory+"/bin/kubectl", nil, "wait", "node/"+bootstrap.state.InstallationID, "--for=condition=Ready", "--timeout=240s")
}

func (bootstrap *guestBootstrap) installProvider(ctx context.Context) error {
	if err := bootstrap.preparePostgreSQLDirectory(); err != nil {
		return err
	}
	objects, err := guestWorkloadObjects(bootstrap.state)
	if err != nil {
		return err
	}
	var jobs, deployment []map[string]any
	for _, object := range objects {
		if object["kind"] == "Job" {
			jobs = append(jobs, object)
			continue
		}
		if object["kind"] == "Deployment" {
			deployment = append(deployment, object)
			continue
		}
		if err := bootstrap.apply(ctx, object); err != nil {
			return err
		}
	}
	if err := bootstrap.run(ctx, 6*time.Minute, guestDirectory+"/bin/kubectl", nil, "--namespace", "cloudring-system", "rollout", "status", "statefulset/postgresql", "--timeout=300s"); err != nil {
		return err
	}
	for _, object := range jobs {
		if err := bootstrap.apply(ctx, object); err != nil {
			return err
		}
		metadata, _ := object["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if !validName(name, 63) {
			return errors.New("guest migration job identity is invalid")
		}
		if err := bootstrap.run(ctx, 4*time.Minute, guestDirectory+"/bin/kubectl", nil, "--namespace", "cloudring-system", "wait", "job/"+name, "--for=condition=Complete", "--timeout=180s"); err != nil {
			return err
		}
	}
	for _, object := range deployment {
		if err := bootstrap.apply(ctx, object); err != nil {
			return err
		}
		metadata, _ := object["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if !validName(name, 63) {
			return errors.New("guest runtime deployment identity is invalid")
		}
		if err := bootstrap.run(ctx, 5*time.Minute, guestDirectory+"/bin/kubectl", nil, "--namespace", "cloudring-system", "rollout", "status", "deployment/"+name, "--timeout=240s"); err != nil {
			return err
		}
	}
	return nil
}

func (bootstrap *guestBootstrap) apply(ctx context.Context, object map[string]any) error {
	payload, err := json.Marshal(object)
	if err != nil {
		return errors.New("encode owned guest workload")
	}
	defer clear(payload)
	return bootstrap.run(ctx, time.Minute, guestDirectory+"/bin/kubectl", payload, "apply", "--server-side", "--field-manager=cloudring-development", "--filename=-")
}

func (bootstrap *guestBootstrap) preparePostgreSQLDirectory() error {
	const name = "postgresql-data"
	if !containsGuestPhase(bootstrap, "postgresql-directory-intent") {
		if _, err := bootstrap.root.Lstat(name); !os.IsNotExist(err) {
			return errors.New("guest database directory already exists without ownership intent")
		}
		bootstrap.journal.Completed = append(bootstrap.journal.Completed, "postgresql-directory-intent")
		if err := bootstrap.saveJournal(); err != nil {
			return err
		}
	}
	if err := bootstrap.root.Mkdir(name, 0o700); err != nil && !os.IsExist(err) {
		return errors.New("create owned guest database directory")
	}
	identity, ownerIsRoot, err := guestInspectDatabaseDirectory(bootstrap.root, name)
	if err != nil {
		return err
	}
	if bootstrap.journal.DatabaseDirectory == nil {
		if !ownerIsRoot {
			return ErrConflict
		}
		directory, err := bootstrap.root.Open(name)
		if err != nil {
			return ErrConflict
		}
		entries, readErr := directory.ReadDir(1)
		closeErr := directory.Close()
		if len(entries) != 0 || readErr != io.EOF || closeErr != nil {
			return errors.New("unrecorded guest database directory is not empty")
		}
		bootstrap.journal.DatabaseDirectory = &identity
		if err := bootstrap.saveJournal(); err != nil {
			return err
		}
	} else if *bootstrap.journal.DatabaseDirectory != identity {
		return errors.New("owned guest database directory was replaced")
	}
	if ownerIsRoot && bootstrap.root.Chown(name, 999, 999) != nil {
		return errors.New("assign owned guest database directory")
	}
	observed, rootOwned, err := guestInspectDatabaseDirectory(bootstrap.root, name)
	if err != nil || rootOwned || observed != identity {
		return ErrConflict
	}
	return nil
}
