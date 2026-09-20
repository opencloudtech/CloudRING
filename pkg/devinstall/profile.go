// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package devinstall installs one disposable, explicitly non-production provider.
// Its KubeVirt substrate is an operator-selected prerequisite, never an owned
// production cluster or a substitute for the production site profile.
package devinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const (
	APIVersion            = "cloudring.org/v1alpha1"
	Kind                  = "CloudRINGDevelopmentInstallation"
	Development           = "development"
	OwnerLabel            = "cloudring.org/development-installation"
	OwnerAnnotation       = "cloudring.org/development-owner"
	ProfileAnnotation     = "cloudring.org/development-profile-sha256"
	maximumProfileBytes   = 1 << 20
	maximumInstallation   = 40
	minimumGuestCPUs      = 4
	minimumGuestMemoryMiB = 8192
	minimumGuestDiskGiB   = 60
)

var (
	ErrInvalidProfile = errors.New("development installation profile is invalid")
	ErrProduction     = errors.New("development installation cannot select a production profile")
	ErrConflict       = errors.New("development installation ownership conflicts with observed state")
	ErrNotFound       = errors.New("development installation is absent")
	dnsName           = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	hexDigest         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitDigest      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	kubernetesUID     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	exactVersion      = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)
	releaseVersion    = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?$`)
)

// Profile contains public artifact pins and explicit infrastructure selection.
// Credentials never belong in a profile or in its deterministic plan.
type Profile struct {
	APIVersion     string  `json:"apiVersion"`
	Kind           string  `json:"kind"`
	Profile        string  `json:"profile"`
	InstallationID string  `json:"installationID"`
	Target         Target  `json:"target"`
	Guest          Guest   `json:"guest"`
	Network        Network `json:"network"`
	Artifacts      BOM     `json:"artifacts"`
}

type Target struct {
	APIServer      string `json:"apiServer"`
	KubeSystemUID  string `json:"kubeSystemUID"`
	Namespace      string `json:"namespace"`
	VirtualMachine string `json:"virtualMachine"`
	Node           string `json:"node"`
	StorageClass   string `json:"storageClass"`
	PriorityClass  string `json:"priorityClass"`
}

type Guest struct {
	CPUs      int `json:"cpus"`
	MemoryMiB int `json:"memoryMiB"`
	DiskGiB   int `json:"diskGiB"`
}

type Network struct {
	GuestCIDR     string   `json:"guestCIDR"`
	PodCIDR       string   `json:"podCIDR"`
	ServiceCIDR   string   `json:"serviceCIDR"`
	PublicOrigin  string   `json:"publicOrigin"`
	EgressDomains []string `json:"egressDomains"`
}

// Download is an exact upstream artifact. Archives are checked before any
// executable is installed in the owned guest.
type Download struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// ImagePin binds kubeadm's upstream image name to its immutable OCI digest.
// The alias is needed by upstream kubeadm; it may never be rebound to a
// different digest while this installation exists.
type ImagePin struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type BOM struct {
	SourceCommit        string     `json:"sourceCommit"`
	Installer           Download   `json:"installer"`
	GuestImage          string     `json:"guestImage"`
	RuntimeImage        string     `json:"runtimeImage"`
	PostgreSQLImage     string     `json:"postgresqlImage"`
	Kubeadm             Download   `json:"kubeadm"`
	Kubelet             Download   `json:"kubelet"`
	Kubectl             Download   `json:"kubectl"`
	Containerd          Download   `json:"containerd"`
	Runc                Download   `json:"runc"`
	CNIPlugins          Download   `json:"cniPlugins"`
	CRICTL              Download   `json:"crictl"`
	Helm                Download   `json:"helm"`
	CiliumChart         Download   `json:"ciliumChart"`
	CiliumImage         string     `json:"ciliumImage"`
	CiliumOperatorImage string     `json:"ciliumOperatorImage"`
	KubernetesImages    []ImagePin `json:"kubernetesImages"`
}

func Parse(reader io.Reader) (Profile, error) {
	var profile Profile
	if reader == nil {
		return profile, ErrInvalidProfile
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maximumProfileBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumProfileBytes || strictjson.DecodeExact(payload, &profile) != nil {
		return Profile{}, ErrInvalidProfile
	}
	if err := Validate(profile, Development); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

// Validate requires an explicit caller mode in addition to the document kind.
// A production caller cannot accept this document even if all resources fit.
func Validate(profile Profile, mode string) error {
	if mode != Development || profile.Profile != Development {
		return ErrProduction
	}
	if profile.APIVersion != APIVersion || profile.Kind != Kind || len(profile.InstallationID) < 3 || !validName(profile.InstallationID, maximumInstallation) {
		return ErrInvalidProfile
	}
	target := profile.Target
	api, err := anonymousHTTPS(target.APIServer)
	if err != nil || api.Path != "" && api.Path != "/" || !kubernetesUID.MatchString(target.KubeSystemUID) ||
		target.KubeSystemUID == "00000000-0000-0000-0000-000000000000" ||
		target.Namespace != "cloudring-dev-"+profile.InstallationID ||
		!validName(target.VirtualMachine, 58) || !validDNS(target.Node) ||
		!validDNS(target.StorageClass) || !validDNS(target.PriorityClass) {
		return ErrInvalidProfile
	}
	guest := profile.Guest
	if guest.CPUs < minimumGuestCPUs || guest.CPUs > 16 || guest.MemoryMiB < minimumGuestMemoryMiB || guest.MemoryMiB > 32768 ||
		guest.MemoryMiB%1024 != 0 || guest.DiskGiB < minimumGuestDiskGiB || guest.DiskGiB > 256 {
		return ErrInvalidProfile
	}
	if err := validateNetwork(profile.Network); err != nil {
		return err
	}
	return validateBOM(profile.Artifacts)
}

func validateNetwork(network Network) error {
	prefixes := make([]netip.Prefix, 0, 3)
	for i, value := range []string{network.GuestCIDR, network.PodCIDR, network.ServiceCIDR} {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix != prefix.Masked() ||
			i == 0 && prefix.Bits() != 30 || i > 0 && (prefix.Bits() < 16 || prefix.Bits() > 24) {
			return ErrInvalidProfile
		}
		for _, previous := range prefixes {
			if previous.Overlaps(prefix) {
				return ErrInvalidProfile
			}
		}
		prefixes = append(prefixes, prefix)
	}
	origin, err := anonymousHTTPS(network.PublicOrigin)
	if err != nil || origin.Path != "" || !validDNS(origin.Hostname()) || origin.Port() == "" {
		return ErrInvalidProfile
	}
	port, err := strconv.Atoi(origin.Port())
	if err != nil || port < 1024 || port > 65535 || !strings.HasSuffix(origin.Hostname(), ".localhost") {
		return ErrInvalidProfile
	}
	if len(network.EgressDomains) == 0 || len(network.EgressDomains) > 64 || !slices.IsSorted(network.EgressDomains) {
		return ErrInvalidProfile
	}
	for i, domain := range network.EgressDomains {
		bare := strings.TrimPrefix(domain, "*.")
		if !validDNS(bare) || !strings.Contains(bare, ".") || net.ParseIP(bare) != nil ||
			strings.HasSuffix(bare, ".localhost") || strings.HasSuffix(bare, ".local") ||
			strings.HasSuffix(bare, ".cluster.local") || i > 0 && domain == network.EgressDomains[i-1] {
			return ErrInvalidProfile
		}
	}
	return nil
}

func validateBOM(bom BOM) error {
	installer, installerErr := anonymousHTTPS(bom.Installer.URL)
	if installerErr != nil || installer.Host != "github.com" ||
		installer.Path != "/opencloudtech/CloudRING/releases/download/"+bom.Installer.Version+"/cloudring-linux-amd64" ||
		!releaseVersion.MatchString(bom.Installer.Version) || !hexDigest.MatchString(bom.Installer.SHA256) {
		return ErrInvalidProfile
	}
	if !commitDigest.MatchString(bom.SourceCommit) || !pinnedImage(bom.GuestImage) ||
		!pinnedImage(bom.RuntimeImage) || !strings.HasPrefix(bom.RuntimeImage, "ghcr.io/opencloudtech/") ||
		!pinnedImage(bom.PostgreSQLImage) || !pinnedImage(bom.CiliumImage) || !pinnedImage(bom.CiliumOperatorImage) ||
		bom.Kubeadm.Version != bom.Kubelet.Version || bom.Kubeadm.Version != bom.Kubectl.Version ||
		!strings.HasPrefix(bom.Kubeadm.Version, "v1.35.") {
		return ErrInvalidProfile
	}
	for _, artifact := range []Download{bom.Kubeadm, bom.Kubelet, bom.Kubectl, bom.Containerd, bom.Runc,
		bom.CNIPlugins, bom.CRICTL, bom.Helm, bom.CiliumChart} {
		location, err := anonymousHTTPS(artifact.URL)
		if err != nil || !hexDigest.MatchString(artifact.SHA256) || !exactVersion.MatchString(artifact.Version) ||
			location.Path == "" || strings.ContainsAny(location.Path, "\\") || strings.Contains(location.Path, "/../") {
			return ErrInvalidProfile
		}
	}
	if len(bom.KubernetesImages) != 7 {
		return ErrInvalidProfile
	}
	roles := map[string]bool{}
	for _, image := range bom.KubernetesImages {
		if !strings.HasPrefix(image.Name, "registry.k8s.io/") && !strings.HasPrefix(image.Name, "docker.io/coredns/coredns:") || strings.ContainsAny(image.Name, "@ \t\n\r") ||
			!strings.HasPrefix(image.Digest, "sha256:") || !hexDigest.MatchString(strings.TrimPrefix(image.Digest, "sha256:")) {
			return ErrInvalidProfile
		}
		alias := strings.TrimPrefix(image.Name, "registry.k8s.io/")
		if strings.HasPrefix(alias, "docker.io/coredns/coredns:") {
			alias = strings.TrimPrefix(alias, "docker.io/")
		}
		name, version, ok := strings.Cut(alias, ":")
		if !ok || roles[name] || version == "" {
			return ErrInvalidProfile
		}
		switch name {
		case "kube-apiserver", "kube-controller-manager", "kube-scheduler", "kube-proxy":
			if version != bom.Kubeadm.Version {
				return ErrInvalidProfile
			}
		case "coredns/coredns", "etcd", "pause":
		default:
			return ErrInvalidProfile
		}
		roles[name] = true
	}
	return nil
}

func Fingerprint(profile Profile) string {
	payload, _ := json.Marshal(profile)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func validName(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && dnsName.MatchString(value)
}

func validDNS(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if !validName(part, 63) {
			return false
		}
	}
	return true
}

func anonymousHTTPS(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Opaque != "" || strings.ContainsAny(value, "\r\n\t ") {
		return nil, ErrInvalidProfile
	}
	return parsed, nil
}

func pinnedImage(value string) bool {
	name, digest, ok := strings.Cut(value, "@sha256:")
	return ok && name != "" && strings.Contains(name, "/") && !strings.ContainsAny(name, " @\t\n\r\\") && hexDigest.MatchString(digest)
}
