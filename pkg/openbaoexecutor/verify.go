// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package openbaoexecutor

import (
	"bytes"
	"errors"
	"io"
	"reflect"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
	"gopkg.in/yaml.v3"
)

type manifestObject struct {
	APIVersion                   string            `yaml:"apiVersion"`
	Kind                         string            `yaml:"kind"`
	Metadata                     manifestMetadata  `yaml:"metadata"`
	AutomountServiceAccountToken *bool             `yaml:"automountServiceAccountToken,omitempty"`
	Spec                         map[string]any    `yaml:"spec,omitempty"`
	Rules                        []manifestRule    `yaml:"rules,omitempty"`
	RoleRef                      *manifestRoleRef  `yaml:"roleRef,omitempty"`
	Subjects                     []manifestSubject `yaml:"subjects,omitempty"`
}

type manifestMetadata struct {
	Name      string            `yaml:"name"`
	Namespace string            `yaml:"namespace,omitempty"`
	Labels    map[string]string `yaml:"labels"`
}

type manifestRule struct {
	APIGroups     []string `yaml:"apiGroups"`
	Resources     []string `yaml:"resources"`
	ResourceNames []string `yaml:"resourceNames,omitempty"`
	Verbs         []string `yaml:"verbs"`
}

type manifestRoleRef struct {
	APIGroup string `yaml:"apiGroup"`
	Kind     string `yaml:"kind"`
	Name     string `yaml:"name"`
}

type manifestSubject struct {
	Kind      string `yaml:"kind"`
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

func verifyRenderedSemantics(profile Profile, manifest []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(manifest))
	decoder.KnownFields(true)
	objects := make(map[string]manifestObject)
	for {
		var object manifestObject
		err := decoder.Decode(&object)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || object.APIVersion == "" || object.Kind == "" || object.Metadata.Name == "" {
			return ErrRenderedManifestDrift
		}
		identity := object.Kind + "/" + object.Metadata.Namespace + "/" + object.Metadata.Name
		if _, duplicate := objects[identity]; duplicate {
			return ErrRenderedManifestDrift
		}
		objects[identity] = object
	}
	if len(objects) != 10 {
		return ErrRenderedManifestDrift
	}
	positive := profile.Contract.WorkloadIdentity
	executor := profile.ExecutorIdentity
	wrongServiceAccount := profile.NegativeIdentities.WrongServiceAccount
	wrongNamespace := profile.NegativeIdentities.WrongNamespace
	scopeName := profile.Lease.Name

	for _, identity := range []struct {
		namespace string
		name      string
	}{
		{executor.Namespace, executor.ServiceAccount},
		{wrongServiceAccount.Namespace, wrongServiceAccount.ServiceAccount},
		{wrongNamespace.Namespace, wrongNamespace.ServiceAccount},
	} {
		object, found := objects["ServiceAccount/"+identity.namespace+"/"+identity.name]
		if !found || !exactServiceAccount(object, identity.namespace, identity.name) {
			return ErrRenderedManifestDrift
		}
	}
	lease, found := objects["Lease/"+profile.Lease.Namespace+"/"+scopeName]
	if !found || !exactLease(lease, profile.Lease.Namespace, scopeName) {
		return ErrRenderedManifestDrift
	}
	clusterRole, found := objects["ClusterRole//"+scopeName]
	if !found || !exactClusterRole(clusterRole, scopeName) {
		return ErrRenderedManifestDrift
	}
	clusterBinding, found := objects["ClusterRoleBinding//"+scopeName]
	if !found || !exactBinding(clusterBinding, "ClusterRoleBinding", "", scopeName, "ClusterRole", scopeName, executor) {
		return ErrRenderedManifestDrift
	}
	executorRole, found := objects["Role/"+executor.Namespace+"/"+scopeName]
	if !found || !exactExecutorRole(executorRole, profile) {
		return ErrRenderedManifestDrift
	}
	executorBinding, found := objects["RoleBinding/"+executor.Namespace+"/"+scopeName]
	if !found || !exactBinding(executorBinding, "RoleBinding", executor.Namespace, scopeName, "Role", scopeName, executor) {
		return ErrRenderedManifestDrift
	}
	negativeRole, found := objects["Role/"+wrongNamespace.Namespace+"/"+scopeName]
	if !found || !exactNegativeRole(negativeRole, wrongNamespace.Namespace, scopeName, positive.ServiceAccount) {
		return ErrRenderedManifestDrift
	}
	negativeBinding, found := objects["RoleBinding/"+wrongNamespace.Namespace+"/"+scopeName]
	if !found || !exactBinding(negativeBinding, "RoleBinding", wrongNamespace.Namespace, scopeName, "Role", scopeName, executor) {
		return ErrRenderedManifestDrift
	}
	return nil
}

func exactServiceAccount(object manifestObject, namespace, name string) bool {
	return object.APIVersion == "v1" && object.Kind == "ServiceAccount" && exactMetadata(object.Metadata, namespace, name) &&
		object.AutomountServiceAccountToken != nil && !*object.AutomountServiceAccountToken && object.Spec == nil && object.Rules == nil && object.RoleRef == nil && object.Subjects == nil
}

func exactLease(object manifestObject, namespace, name string) bool {
	return object.APIVersion == "coordination.k8s.io/v1" && object.Kind == "Lease" && exactMetadata(object.Metadata, namespace, name) &&
		object.AutomountServiceAccountToken == nil && object.Spec != nil && len(object.Spec) == 0 && object.Rules == nil && object.RoleRef == nil && object.Subjects == nil
}

func exactClusterRole(object manifestObject, name string) bool {
	wantRules := []manifestRule{
		{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews"}, Verbs: []string{"create"}},
		{APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews"}, Verbs: []string{"create"}},
	}
	return object.APIVersion == "rbac.authorization.k8s.io/v1" && object.Kind == "ClusterRole" && exactMetadata(object.Metadata, "", name) &&
		object.AutomountServiceAccountToken == nil && object.Spec == nil && reflect.DeepEqual(object.Rules, wantRules) && object.RoleRef == nil && object.Subjects == nil
}

func exactExecutorRole(object manifestObject, profile Profile) bool {
	wantRules := []manifestRule{
		{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, ResourceNames: []string{profile.Lease.Name}, Verbs: []string{"get", "update"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{profile.ExecutorIdentity.ServiceAccount, profile.Contract.WorkloadIdentity.ServiceAccount, profile.NegativeIdentities.WrongServiceAccount.ServiceAccount}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{profile.Contract.WorkloadIdentity.ServiceAccount, profile.NegativeIdentities.WrongServiceAccount.ServiceAccount}, Verbs: []string{"create"}},
	}
	return object.APIVersion == "rbac.authorization.k8s.io/v1" && object.Kind == "Role" && exactMetadata(object.Metadata, profile.ExecutorIdentity.Namespace, profile.Lease.Name) &&
		object.AutomountServiceAccountToken == nil && object.Spec == nil && reflect.DeepEqual(object.Rules, wantRules) && object.RoleRef == nil && object.Subjects == nil
}

func exactNegativeRole(object manifestObject, namespace, name, serviceAccount string) bool {
	wantRules := []manifestRule{
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{serviceAccount}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{serviceAccount}, Verbs: []string{"create"}},
	}
	return object.APIVersion == "rbac.authorization.k8s.io/v1" && object.Kind == "Role" && exactMetadata(object.Metadata, namespace, name) &&
		object.AutomountServiceAccountToken == nil && object.Spec == nil && reflect.DeepEqual(object.Rules, wantRules) && object.RoleRef == nil && object.Subjects == nil
}

func exactBinding(object manifestObject, kind, namespace, name, roleKind, roleName string, subject openbaoauth.WorkloadIdentity) bool {
	wantRoleRef := &manifestRoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: roleKind, Name: roleName}
	wantSubjects := []manifestSubject{{Kind: "ServiceAccount", Name: subject.ServiceAccount, Namespace: subject.Namespace}}
	return object.APIVersion == "rbac.authorization.k8s.io/v1" && object.Kind == kind && exactMetadata(object.Metadata, namespace, name) &&
		object.AutomountServiceAccountToken == nil && object.Spec == nil && object.Rules == nil && reflect.DeepEqual(object.RoleRef, wantRoleRef) && reflect.DeepEqual(object.Subjects, wantSubjects)
}

func exactMetadata(metadata manifestMetadata, namespace, name string) bool {
	return metadata.Name == name && metadata.Namespace == namespace && reflect.DeepEqual(metadata.Labels, map[string]string{"app.kubernetes.io/part-of": "cloudring-secret-manager"})
}
