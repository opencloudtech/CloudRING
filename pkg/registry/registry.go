// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package registry validates the provider-neutral CloudRING module registry
// contract. It validates metadata and lifecycle plans only; it never loads or
// executes a service implementation.
package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

const SchemaVersion = "cloudring.module-registry/v1"

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

type Registry struct {
	SchemaVersion        string               `json:"schemaVersion"`
	RegistryID           string               `json:"registryId"`
	ModelVersion         string               `json:"modelVersion"`
	SourceSafety         SourceSafety         `json:"sourceSafety"`
	DependencyResolution DependencyResolution `json:"dependencyResolution"`
	Modules              []Module             `json:"modules"`
	PlanRequests         []PlanRequest        `json:"planRequests"`
}

type SourceSafety struct {
	SyntheticFixture                  bool `json:"syntheticFixture"`
	ContainsServiceImplementationRefs bool `json:"containsServiceImplementationReferences"`
	ContainsProviderEndpoints         bool `json:"containsProviderEndpoints"`
	ContainsSecrets                   bool `json:"containsSecrets"`
	MutatesServices                   bool `json:"mutatesServices"`
}

type DependencyResolution struct {
	Strategy                string `json:"strategy"`
	CyclePolicy             string `json:"cyclePolicy"`
	MissingDependencyPolicy string `json:"missingDependencyPolicy"`
	EvidenceRef             string `json:"evidenceRef"`
}

type Module struct {
	ID                        string       `json:"id"`
	DisplayName               string       `json:"displayName"`
	PackageRef                string       `json:"packageRef"`
	Channel                   string       `json:"channel"`
	Version                   string       `json:"version"`
	State                     string       `json:"state"`
	LifecycleStates           []string     `json:"lifecycleStates"`
	Dependencies              []Dependency `json:"dependencies"`
	EntitlementScope          string       `json:"entitlementScope"`
	Operations                Operations   `json:"operations"`
	ServiceImplementationRefs *[]string    `json:"serviceImplementationRefs,omitempty"`
}

type Dependency struct {
	ModuleID string `json:"moduleId"`
	State    string `json:"state"`
}

type Operations struct {
	Install   Operation `json:"install"`
	Update    Operation `json:"update"`
	Remove    Operation `json:"remove"`
	Suspend   Operation `json:"suspend"`
	Deprecate Operation `json:"deprecate"`
}

type Operation struct {
	Action             string `json:"action"`
	OperationID        string `json:"operationId"`
	Idempotent         bool   `json:"idempotent"`
	IdempotencyKey     string `json:"idempotencyKey"`
	PolicyAware        bool   `json:"policyAware"`
	AuditReceiptRef    string `json:"auditReceiptRef"`
	EvidenceReceiptRef string `json:"evidenceReceiptRef"`
	RollbackRequired   bool   `json:"rollbackRequired"`
	RollbackHookRef    string `json:"rollbackHookRef"`
	NextAction         string `json:"nextAction"`
}

type PlanRequest struct {
	Name          string `json:"name"`
	ModuleID      string `json:"moduleId"`
	Action        string `json:"action"`
	CurrentState  string `json:"currentState"`
	TargetVersion string `json:"targetVersion"`
}

type ValidationError struct {
	Path    string
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("path=%s code=%s message=%s", e.Path, e.Code, e.Message)
}

func Parse(data []byte) (Registry, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var registry Registry
	if err := decoder.Decode(&registry); err != nil {
		return Registry{}, fmt.Errorf("decode module registry: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Registry{}, fmt.Errorf("decode module registry: trailing JSON")
		}
		return Registry{}, fmt.Errorf("decode module registry: %w", err)
	}
	if err := registry.Validate(); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func (r Registry) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return invalid("schemaVersion", "schema.version", "must be the CloudRING module registry v1 contract")
	}
	if !identifierPattern.MatchString(r.RegistryID) {
		return invalid("registryId", "registry.id", "must be a lowercase stable identifier")
	}
	if strings.TrimSpace(r.ModelVersion) == "" {
		return invalid("modelVersion", "registry.model-version", "must not be empty")
	}
	if err := r.SourceSafety.validate(); err != nil {
		return err
	}
	if err := r.DependencyResolution.validate(); err != nil {
		return err
	}
	if len(r.Modules) == 0 {
		return invalid("modules", "modules.empty", "at least one module is required")
	}

	moduleIndex := make(map[string]Module, len(r.Modules))
	for index, module := range r.Modules {
		if err := validateModule(index, module, moduleIndex); err != nil {
			return err
		}
		moduleIndex[module.ID] = module
	}
	if err := validateDependencies(r.Modules, moduleIndex); err != nil {
		return err
	}
	if len(r.PlanRequests) == 0 {
		return invalid("planRequests", "plans.empty", "at least one plan request is required")
	}
	seenPlans := make(map[string]struct{}, len(r.PlanRequests))
	for index, plan := range r.PlanRequests {
		if err := validatePlan(index, plan, moduleIndex, seenPlans); err != nil {
			return err
		}
	}
	return nil
}

func (s SourceSafety) validate() error {
	if !s.SyntheticFixture {
		return invalid("sourceSafety.syntheticFixture", "source-safety.synthetic", "must be true for a public contract fixture")
	}
	if s.ContainsServiceImplementationRefs {
		return invalid("sourceSafety.containsServiceImplementationReferences", "source-safety.implementation-reference", "must be false")
	}
	if s.ContainsProviderEndpoints {
		return invalid("sourceSafety.containsProviderEndpoints", "source-safety.provider-endpoint", "must be false")
	}
	if s.ContainsSecrets {
		return invalid("sourceSafety.containsSecrets", "source-safety.secret", "must be false")
	}
	if s.MutatesServices {
		return invalid("sourceSafety.mutatesServices", "source-safety.mutation", "must be false")
	}
	return nil
}

func (d DependencyResolution) validate() error {
	if d.Strategy != "topological" {
		return invalid("dependencyResolution.strategy", "dependencies.strategy", "must be topological")
	}
	if d.CyclePolicy != "block" {
		return invalid("dependencyResolution.cyclePolicy", "dependencies.cycle-policy", "must be block")
	}
	if d.MissingDependencyPolicy != "block" {
		return invalid("dependencyResolution.missingDependencyPolicy", "dependencies.missing-policy", "must be block")
	}
	if strings.TrimSpace(d.EvidenceRef) == "" {
		return invalid("dependencyResolution.evidenceRef", "dependencies.evidence", "must not be empty")
	}
	return nil
}

func validateModule(index int, module Module, known map[string]Module) error {
	prefix := fmt.Sprintf("modules[%d]", index)
	if !identifierPattern.MatchString(module.ID) {
		return invalid(prefix+".id", "module.id", "must be a lowercase stable identifier")
	}
	if _, exists := known[module.ID]; exists {
		return invalid(prefix+".id", "module.id.duplicate", "module IDs must be unique")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "displayName", value: module.DisplayName},
		{name: "channel", value: module.Channel},
		{name: "version", value: module.Version},
		{name: "entitlementScope", value: module.EntitlementScope},
	} {
		if strings.TrimSpace(field.value) == "" {
			return invalid(prefix+"."+field.name, "module.required", "must not be empty")
		}
	}
	if !validPackageRef(module.PackageRef) {
		return invalid(prefix+".packageRef", "module.package-reference", "must be a relative provider-neutral package path")
	}
	if !validModuleState(module.State) {
		return invalid(prefix+".state", "module.state", "is not a supported lifecycle state")
	}
	if err := validateLifecycleStates(prefix, module.LifecycleStates); err != nil {
		return err
	}
	if module.ServiceImplementationRefs != nil {
		return invalid(prefix+".serviceImplementationRefs", "module.implementation-reference", "public registry records must not carry service implementation references")
	}
	for dependencyIndex, dependency := range module.Dependencies {
		path := fmt.Sprintf("%s.dependencies[%d]", prefix, dependencyIndex)
		if !identifierPattern.MatchString(dependency.ModuleID) {
			return invalid(path+".moduleId", "dependency.module-id", "must be a lowercase stable identifier")
		}
		if dependency.ModuleID == module.ID {
			return invalid(path+".moduleId", "dependency.self", "a module cannot depend on itself")
		}
		if dependency.State != "installed" && dependency.State != "installable" {
			return invalid(path+".state", "dependency.state", "must be installed or installable")
		}
	}
	return validateOperations(prefix+".operations", module.Operations)
}

func validateLifecycleStates(prefix string, states []string) error {
	required := map[string]bool{
		"installable":   true,
		"installed":     true,
		"suspended":     true,
		"deprecated":    true,
		"not-installed": true,
	}
	seen := make(map[string]struct{}, len(states))
	for index, state := range states {
		if _, exists := required[state]; !exists {
			return invalid(fmt.Sprintf("%s.lifecycleStates[%d]", prefix, index), "module.lifecycle-state", "is not supported")
		}
		if _, exists := seen[state]; exists {
			return invalid(fmt.Sprintf("%s.lifecycleStates[%d]", prefix, index), "module.lifecycle-state.duplicate", "lifecycle states must be unique")
		}
		seen[state] = struct{}{}
	}
	if len(seen) != len(required) {
		return invalid(prefix+".lifecycleStates", "module.lifecycle-state.missing", "all v1 lifecycle states are required")
	}
	return nil
}

func validateOperations(prefix string, operations Operations) error {
	items := []struct {
		name  string
		value Operation
	}{
		{"install", operations.Install},
		{"update", operations.Update},
		{"remove", operations.Remove},
		{"suspend", operations.Suspend},
		{"deprecate", operations.Deprecate},
	}
	for _, item := range items {
		path := prefix + "." + item.name
		if item.value.Action != item.name {
			return invalid(path+".action", "operation.action", "must match the operation key")
		}
		for _, field := range []struct {
			name  string
			value string
		}{
			{name: "operationId", value: item.value.OperationID},
			{name: "idempotencyKey", value: item.value.IdempotencyKey},
			{name: "auditReceiptRef", value: item.value.AuditReceiptRef},
			{name: "evidenceReceiptRef", value: item.value.EvidenceReceiptRef},
			{name: "rollbackHookRef", value: item.value.RollbackHookRef},
			{name: "nextAction", value: item.value.NextAction},
		} {
			if strings.TrimSpace(field.value) == "" {
				return invalid(path+"."+field.name, "operation.required", "must not be empty")
			}
		}
		if !item.value.Idempotent || !item.value.PolicyAware || !item.value.RollbackRequired {
			return invalid(path, "operation.safety-flags", "idempotent, policyAware, and rollbackRequired must all be true")
		}
	}
	return nil
}

func validateDependencies(modules []Module, known map[string]Module) error {
	for index, module := range modules {
		for dependencyIndex, dependency := range module.Dependencies {
			if _, exists := known[dependency.ModuleID]; !exists {
				return invalid(fmt.Sprintf("modules[%d].dependencies[%d].moduleId", index, dependencyIndex), "dependency.missing", "dependency module is not declared")
			}
		}
	}
	visiting := make(map[string]bool, len(modules))
	visited := make(map[string]bool, len(modules))
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return invalid("modules.dependencies", "dependency.cycle", "dependency graph must be acyclic")
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		module := known[id]
		for _, dependency := range module.Dependencies {
			if err := visit(dependency.ModuleID); err != nil {
				return err
			}
		}
		delete(visiting, id)
		visited[id] = true
		return nil
	}
	for _, module := range modules {
		if err := visit(module.ID); err != nil {
			return err
		}
	}
	return nil
}

func validatePlan(index int, plan PlanRequest, modules map[string]Module, seen map[string]struct{}) error {
	prefix := fmt.Sprintf("planRequests[%d]", index)
	if !identifierPattern.MatchString(plan.Name) {
		return invalid(prefix+".name", "plan.name", "must be a lowercase stable identifier")
	}
	if _, exists := seen[plan.Name]; exists {
		return invalid(prefix+".name", "plan.name.duplicate", "plan names must be unique")
	}
	seen[plan.Name] = struct{}{}
	module, exists := modules[plan.ModuleID]
	if !exists {
		return invalid(prefix+".moduleId", "plan.module-missing", "plan module is not declared")
	}
	if !validOperation(plan.Action) {
		return invalid(prefix+".action", "plan.action", "is not a supported operation")
	}
	if !validModuleState(plan.CurrentState) || strings.TrimSpace(plan.CurrentState) == "" {
		return invalid(prefix+".currentState", "plan.current-state", "must be a supported lifecycle state")
	}
	if strings.TrimSpace(plan.TargetVersion) == "" || plan.TargetVersion != module.Version {
		return invalid(prefix+".targetVersion", "plan.target-version", "must match the declared module version")
	}
	return nil
}

func validPackageRef(value string) bool {
	if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || strings.Contains(value, "://") || strings.ContainsRune(value, '\\') {
		return false
	}
	clean := path.Clean(value)
	return clean == value && !path.IsAbs(value) && clean != "." && !strings.HasPrefix(clean, "../")
}

func validModuleState(value string) bool {
	switch value {
	case "installable", "installed", "suspended", "deprecated", "not-installed":
		return true
	default:
		return false
	}
}

func validOperation(value string) bool {
	switch value {
	case "install", "update", "remove", "suspend", "deprecate":
		return true
	default:
		return false
	}
}

func invalid(path, code, message string) error {
	return &ValidationError{Path: path, Code: code, Message: message}
}
