// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

// Package roadmapprogram validates the canonical CloudRING delivery roadmap.
package roadmapprogram

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	APIVersionDeliveryRoadmap = "roadmap.cloudring.org/v1alpha1"
	KindDeliveryRoadmap       = "DeliveryRoadmap"
	maxRoadmapFileBytes       = 1 << 20

	StatusNotStarted Status = "not_started"
	StatusInProgress Status = "in_progress"
	StatusBlocked    Status = "blocked"
	StatusDelivered  Status = "delivered"
)

var (
	knownDeploymentTargets = []string{
		"public_clean_room",
		"hub",
		"independent_provider",
		"region_primary",
		"region_secondary",
		"federation_provider_a",
		"federation_provider_b",
	}
	requiredInvariants = []string{
		"complete_in_dependency_order",
		"reusable_implementation_is_oss",
		"public_clean_room_proof_precedes_downstreams",
		"protected_main_only",
		"exact_downstream_pins",
		"every_provider_pin_passes_safepush_stage_9",
		"deploy_every_goal_to_hub_cloudring_org",
		"cumulative_live_regression_every_goal",
		"signed_prerelease_sbom_and_provenance_every_goal",
		"no_scaffold_or_fixture_readiness_claims",
		"final_broad_security_review_on_1_0_path_is_G27",
		"every_post_1_0_track_requires_terminal_security_review",
		"cloudring_1_0_does_not_depend_on_multi_region_or_federation",
		"federation_is_opt_in_and_never_a_standalone_provider_dependency",
	}
	requiredGoalOrder           = canonicalGoalOrder()
	requirementIDPattern        = regexp.MustCompile(`^CR-G[0-9]{2}-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$`)
	requirementReferencePattern = regexp.MustCompile(`\bCR-[A-Z0-9]+(?:-[A-Z0-9]+)+\b`)
	legacyRequirementIDPattern  = regexp.MustCompile(`^CR-[A-Z0-9]+(?:-[A-Z0-9]+)+$`)
	goalIDPattern               = regexp.MustCompile(`^G[0-9]{2}$`)
)

// Status is the declared delivery state of a goal.
type Status string

// Roadmap is the roadmap.yaml delivery-program contract.
type Roadmap struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec Spec `yaml:"spec"`
}

// Spec describes the delivery graph and its repository-wide invariants.
type Spec struct {
	ExecutionContract        string   `yaml:"executionContract"`
	TargetArchitecture       string   `yaml:"targetArchitecture"`
	CurrentState             string   `yaml:"currentState"`
	IssueMap                 string   `yaml:"issueMap"`
	LegacyWorkMap            string   `yaml:"legacyWorkMap"`
	HubPrerequisites         string   `yaml:"hubPrerequisites"`
	MeasurementContract      string   `yaml:"measurementContract"`
	EvidencePolicy           string   `yaml:"evidencePolicy"`
	VerificationMatrix       string   `yaml:"verificationMatrix"`
	StateSchema              string   `yaml:"stateSchema"`
	EvidenceSchema           string   `yaml:"evidenceSchema"`
	DefaultDeploymentTargets []string `yaml:"defaultDeploymentTargets"`
	DeliveryOrder            []Goal   `yaml:"deliveryOrder"`
	Invariant                []string `yaml:"invariant"`
}

// Goal is one deliverable node in the roadmap dependency graph.
type Goal struct {
	ID                string   `yaml:"id"`
	File              string   `yaml:"file"`
	DependsOn         []string `yaml:"dependsOn"`
	RequirementIDs    []string `yaml:"requirementIds"`
	Status            Status   `yaml:"status"`
	ReleaseTrack      string   `yaml:"releaseTrack"`
	LiveDeployment    string   `yaml:"liveDeployment"`
	DeploymentTargets []string `yaml:"deploymentTargets"`
}

// Parse strictly decodes exactly one roadmap document. Unknown fields,
// duplicate mapping keys, aliases and trailing documents fail closed.
func Parse(data []byte) (*Roadmap, error) {
	if len(data) == 0 || len(data) > maxRoadmapFileBytes {
		return nil, errors.New("roadmap YAML must be a non-empty bounded document")
	}

	var node yaml.Node
	nodeDecoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := nodeDecoder.Decode(&node); err != nil {
		return nil, fmt.Errorf("parse roadmap YAML: %w", err)
	}
	if err := validateYAMLTree(&node); err != nil {
		return nil, fmt.Errorf("parse roadmap YAML: %w", err)
	}
	var trailing yaml.Node
	if err := nodeDecoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse roadmap YAML: unexpected trailing document")
	}

	var roadmap Roadmap
	strictDecoder := yaml.NewDecoder(bytes.NewReader(data))
	strictDecoder.KnownFields(true)
	if err := strictDecoder.Decode(&roadmap); err != nil {
		return nil, fmt.Errorf("parse roadmap YAML: %w", err)
	}
	if err := strictDecoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse roadmap YAML: unexpected trailing document")
	}
	return &roadmap, nil
}

// Load reads roadmap.yaml below root and validates the complete roadmap tree.
func Load(root string) (*Roadmap, error) {
	return LoadWithOptions(root, ValidationOptions{})
}

// LoadWithOptions reads and validates a roadmap with an explicitly bounded
// evidence resolver. A nil resolver is the safe default: any state that cites
// evidence fails closed because the referenced bytes cannot be inspected.
func LoadWithOptions(root string, options ValidationOptions) (*Roadmap, error) {
	repository, err := openRoadmapRoot(root)
	if err != nil {
		return nil, err
	}
	defer repository.Close()

	data, err := readRegular(repository, "roadmap.yaml")
	if err != nil {
		return nil, fmt.Errorf("read roadmap.yaml: %w", err)
	}
	roadmap, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if err := roadmap.validate(repository, options); err != nil {
		return nil, err
	}
	return roadmap, nil
}

// ValidateDir validates the roadmap rooted at root.
func ValidateDir(root string) error {
	_, err := Load(root)
	return err
}

// ValidateDirWithOptions validates a roadmap using explicit resolver and clock
// inputs suitable for a CI or goal-verifier trust boundary.
func ValidateDirWithOptions(root string, options ValidationOptions) error {
	_, err := LoadWithOptions(root, options)
	return err
}

// Validate checks a parsed roadmap against files below root.
func (r *Roadmap) Validate(root string) error {
	return r.ValidateWithOptions(root, ValidationOptions{})
}

// ValidateWithOptions validates a parsed roadmap with explicit evidence inputs.
func (r *Roadmap) ValidateWithOptions(root string, options ValidationOptions) error {
	repository, err := openRoadmapRoot(root)
	if err != nil {
		return err
	}
	defer repository.Close()
	return r.validate(repository, options)
}

func (r *Roadmap) validate(repository *os.Root, options ValidationOptions) error {
	if r == nil {
		return errors.New("roadmap is nil")
	}

	var blockers []string
	if r.APIVersion != APIVersionDeliveryRoadmap {
		blockers = append(blockers, fmt.Sprintf("apiVersion must be %s, got %q", APIVersionDeliveryRoadmap, r.APIVersion))
	}
	if r.Kind != KindDeliveryRoadmap {
		blockers = append(blockers, fmt.Sprintf("kind must be %s, got %q", KindDeliveryRoadmap, r.Kind))
	}
	if strings.TrimSpace(r.Metadata.Name) == "" {
		blockers = append(blockers, "metadata.name is required")
	}

	for _, contract := range r.Spec.contractFiles() {
		if err := validateFileReference(repository, contract.name); err != nil {
			blockers = append(blockers, contract.label+": "+err.Error())
		}
	}
	stateSchema, err := compileRoadmapSchema(repository, r.Spec.StateSchema, stateSchemaShape)
	if err != nil {
		blockers = append(blockers, "stateSchema: "+err.Error())
	}
	evidenceSchema, err := compileRoadmapSchema(repository, r.Spec.EvidenceSchema, evidenceSchemaShape)
	if err != nil {
		blockers = append(blockers, "evidenceSchema: "+err.Error())
	}
	legacyRequirementOwners, err := loadLegacyRequirementOwners(repository)
	if err != nil {
		blockers = append(blockers, "coverage: "+err.Error())
	}

	if duplicates := duplicateValues(r.Spec.DefaultDeploymentTargets); len(duplicates) != 0 {
		blockers = append(blockers, "duplicate default deployment targets: "+strings.Join(duplicates, ", "))
	}
	blockers = append(blockers, validateDeploymentTargets("default deployment targets", r.Spec.DefaultDeploymentTargets)...)
	for _, required := range []string{"public_clean_room", "hub"} {
		if !contains(r.Spec.DefaultDeploymentTargets, required) {
			blockers = append(blockers, "default deployment targets must include "+required)
		}
	}

	goals := make(map[string]*Goal, len(r.Spec.DeliveryOrder))
	order := make([]string, 0, len(r.Spec.DeliveryOrder))
	requirements := make(map[string]string)
	for index := range r.Spec.DeliveryOrder {
		goal := &r.Spec.DeliveryOrder[index]
		order = append(order, goal.ID)
		if strings.TrimSpace(goal.ID) == "" {
			blockers = append(blockers, fmt.Sprintf("deliveryOrder[%d] has an empty id", index))
			continue
		}
		if _, exists := goals[goal.ID]; exists {
			blockers = append(blockers, "duplicate goal id: "+goal.ID)
			continue
		}
		goals[goal.ID] = goal

		if !validStatus(goal.Status) {
			blockers = append(blockers, fmt.Sprintf("%s: invalid status %q", goal.ID, goal.Status))
		}
		if goal.LiveDeployment != "required" {
			blockers = append(blockers, fmt.Sprintf("%s: liveDeployment must be required", goal.ID))
		}
		if len(goal.RequirementIDs) == 0 {
			blockers = append(blockers, goal.ID+": requirementIds must not be empty")
		}
		if duplicates := duplicateValues(goal.RequirementIDs); len(duplicates) != 0 {
			blockers = append(blockers, fmt.Sprintf("%s: duplicate requirement ids: %s", goal.ID, strings.Join(duplicates, ", ")))
		}
		for _, requirementID := range goal.RequirementIDs {
			if strings.TrimSpace(requirementID) == "" {
				blockers = append(blockers, goal.ID+": requirementIds must not contain empty values")
				continue
			}
			if !requirementIDPattern.MatchString(requirementID) || !strings.HasPrefix(requirementID, "CR-"+goal.ID+"-") {
				blockers = append(blockers, fmt.Sprintf("%s: invalid requirement id %q", goal.ID, requirementID))
			}
			if owner, exists := requirements[requirementID]; exists {
				blockers = append(blockers, fmt.Sprintf("requirement id %s is shared by %s and %s", requirementID, owner, goal.ID))
			} else {
				requirements[requirementID] = goal.ID
			}
		}
		if duplicates := duplicateValues(goal.DependsOn); len(duplicates) != 0 {
			blockers = append(blockers, fmt.Sprintf("%s: duplicate dependencies: %s", goal.ID, strings.Join(duplicates, ", ")))
		}
		if duplicates := duplicateValues(goal.DeploymentTargets); len(duplicates) != 0 {
			blockers = append(blockers, fmt.Sprintf("%s: duplicate deployment targets: %s", goal.ID, strings.Join(duplicates, ", ")))
		}
		blockers = append(blockers, validateDeploymentTargets(goal.ID+": deployment targets", goal.DeploymentTargets)...)

		targets := goal.DeploymentTargets
		if len(targets) == 0 {
			targets = r.Spec.DefaultDeploymentTargets
		}
		for _, required := range []string{"public_clean_room", "hub"} {
			if !contains(targets, required) {
				blockers = append(blockers, fmt.Sprintf("%s: deployment targets must include %s", goal.ID, required))
			}
		}

		body, err := readRegular(repository, goal.File)
		if err != nil {
			blockers = append(blockers, fmt.Sprintf("%s: cannot read goal file %q: %v", goal.ID, goal.File, err))
			continue
		}
		if headingGoalID(body) != goal.ID {
			blockers = append(blockers, fmt.Sprintf("%s: goal file heading must start with %s", goal.ID, goal.ID))
		}
		blockers = append(blockers, validateGoalRequirementReferences(goal, body, legacyRequirementOwners)...)
	}

	if !slices.Equal(order, requiredGoalOrder) {
		blockers = append(blockers, "deliveryOrder must be exactly G00-G24, G27, G25, G26")
	}
	blockers = append(blockers, validateCanonicalDependencies(goals)...)
	blockers = append(blockers, dependencyCycles(goals)...)
	blockers = append(blockers, validateStatuses(goals)...)
	blockers = append(blockers, validateReleaseBoundary(goals)...)
	blockers = append(blockers, validateInvariants(r.Spec.Invariant)...)
	if stateSchema != nil && evidenceSchema != nil {
		blockers = append(blockers, validateStateRecords(repository, r, stateSchema, evidenceSchema, options)...)
	}

	if len(blockers) != 0 {
		slices.Sort(blockers)
		return errors.New(strings.Join(blockers, "\n"))
	}
	return nil
}

// CanTransition verifies the canonical state machine and dependency barrier.
func (r *Roadmap) CanTransition(goalID string, target Status) error {
	if r == nil {
		return errors.New("roadmap is nil")
	}
	if !validStatus(target) {
		return fmt.Errorf("invalid target status %q", target)
	}
	goal, exists := r.goalIndex()[goalID]
	if !exists {
		return fmt.Errorf("goal %s does not exist", goalID)
	}
	if goal.Status == target {
		return nil
	}
	if !allowedTransition(goal.Status, target) {
		return fmt.Errorf("%s cannot transition from %s to %s", goalID, goal.Status, target)
	}
	if target != StatusInProgress && target != StatusDelivered {
		return nil
	}

	goals := r.goalIndex()
	var unmet []string
	for _, dependency := range goal.DependsOn {
		prerequisite, found := goals[dependency]
		if !found || prerequisite.Status != StatusDelivered {
			unmet = append(unmet, dependency)
		}
	}
	if len(unmet) != 0 {
		return fmt.Errorf("%s cannot transition to %s; dependencies are not delivered: %s", goalID, target, strings.Join(unmet, ", "))
	}
	return nil
}

func (s Spec) contractFiles() []struct {
	label string
	name  string
} {
	return []struct {
		label string
		name  string
	}{
		{label: "executionContract", name: s.ExecutionContract},
		{label: "targetArchitecture", name: s.TargetArchitecture},
		{label: "currentState", name: s.CurrentState},
		{label: "issueMap", name: s.IssueMap},
		{label: "legacyWorkMap", name: s.LegacyWorkMap},
		{label: "hubPrerequisites", name: s.HubPrerequisites},
		{label: "measurementContract", name: s.MeasurementContract},
		{label: "evidencePolicy", name: s.EvidencePolicy},
		{label: "verificationMatrix", name: s.VerificationMatrix},
		{label: "stateSchema", name: s.StateSchema},
		{label: "evidenceSchema", name: s.EvidenceSchema},
	}
}

func openRoadmapRoot(root string) (*os.Root, error) {
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.New("resolve roadmap root")
	}
	info, err := os.Lstat(abs)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("roadmap root is not an exact directory")
	}
	repository, err := os.OpenRoot(abs)
	if err != nil {
		return nil, errors.New("open confined roadmap root")
	}
	return repository, nil
}

func validateFileReference(root *os.Root, name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("file reference is required")
	}
	_, err := readRegular(root, name)
	return err
}

func readRegular(root *os.Root, name string) ([]byte, error) {
	normalized := filepath.FromSlash(name)
	if name == "" || filepath.IsAbs(normalized) || filepath.Clean(normalized) != normalized || normalized == "." {
		return nil, errors.New("file reference must be a clean relative path below the roadmap root")
	}
	parts := strings.Split(normalized, string(filepath.Separator))
	for index := range parts {
		component := filepath.Join(parts[:index+1]...)
		info, err := root.Lstat(component)
		if err != nil {
			return nil, errors.New("file reference must identify an exact bounded regular file below the roadmap root")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("file reference must not traverse symbolic links")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return nil, errors.New("file reference parent must be an exact directory")
		}
	}
	info, err := root.Lstat(normalized)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRoadmapFileBytes {
		return nil, errors.New("file reference must identify an exact bounded regular file below the roadmap root")
	}
	data, err := root.ReadFile(normalized)
	if err != nil || int64(len(data)) != info.Size() {
		return nil, errors.New("read exact roadmap file")
	}
	after, err := root.Lstat(normalized)
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() || after.ModTime() != info.ModTime() {
		return nil, errors.New("roadmap file changed while reading")
	}
	return data, nil
}

func validateDeploymentTargets(label string, targets []string) []string {
	var blockers []string
	for _, target := range targets {
		if strings.TrimSpace(target) == "" {
			blockers = append(blockers, label+" must not contain empty values")
			continue
		}
		if !contains(knownDeploymentTargets, target) {
			blockers = append(blockers, fmt.Sprintf("%s contains unknown target %q", label, target))
		}
	}
	return blockers
}

func loadLegacyRequirementOwners(root *os.Root) (map[string]string, error) {
	body, err := readRegular(root, "COVERAGE.md")
	if err != nil {
		return nil, err
	}
	owners := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "| CR-") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) < 4 {
			return nil, errors.New("legacy requirement mapping row is malformed")
		}
		legacyID := strings.TrimSpace(columns[1])
		owner := strings.TrimSpace(columns[2])
		if !legacyRequirementIDPattern.MatchString(legacyID) || !goalIDPattern.MatchString(owner) {
			return nil, errors.New("legacy requirement mapping row is invalid")
		}
		if previous, exists := owners[legacyID]; exists && previous != owner {
			return nil, fmt.Errorf("legacy requirement %s has conflicting owners", legacyID)
		}
		owners[legacyID] = owner
	}
	return owners, nil
}

func validateGoalRequirementReferences(goal *Goal, body []byte, legacyOwners map[string]string) []string {
	seen := make(map[string]bool)
	var blockers []string
	for _, match := range requirementReferencePattern.FindAllString(string(body), -1) {
		if seen[match] {
			continue
		}
		seen[match] = true
		if contains(goal.RequirementIDs, match) || legacyOwners[match] == goal.ID {
			continue
		}
		blockers = append(blockers, fmt.Sprintf("%s: goal file references undeclared requirement %s", goal.ID, match))
	}
	return blockers
}

func validateYAMLTree(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode {
		return errors.New("YAML aliases are not allowed")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]bool, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index].Value
			if seen[key] {
				return fmt.Errorf("duplicate YAML mapping key %q", key)
			}
			seen[key] = true
		}
	}
	for _, child := range node.Content {
		if err := validateYAMLTree(child); err != nil {
			return err
		}
	}
	return nil
}

func canonicalGoalOrder() []string {
	goals := make([]string, 0, 28)
	for number := 0; number <= 24; number++ {
		goals = append(goals, fmt.Sprintf("G%02d", number))
	}
	return append(goals, "G27", "G25", "G26")
}

func validateCanonicalDependencies(goals map[string]*Goal) []string {
	var blockers []string
	for number := 0; number <= 24; number++ {
		id := fmt.Sprintf("G%02d", number)
		goal, exists := goals[id]
		if !exists {
			blockers = append(blockers, id+" goal is required")
			continue
		}
		var expected []string
		if number > 0 {
			expected = []string{fmt.Sprintf("G%02d", number-1)}
		}
		if !slices.Equal(goal.DependsOn, expected) {
			blockers = append(blockers, fmt.Sprintf("%s: dependsOn must be exactly %v", id, expected))
		}
	}
	for id, expected := range map[string][]string{
		"G27": {"G24"},
		"G25": {"G27"},
		"G26": {"G27"},
	} {
		goal, exists := goals[id]
		if !exists {
			blockers = append(blockers, id+" goal is required")
			continue
		}
		if !slices.Equal(goal.DependsOn, expected) {
			blockers = append(blockers, fmt.Sprintf("%s: dependsOn must be exactly %v", id, expected))
		}
	}
	return blockers
}

func validateStatuses(goals map[string]*Goal) []string {
	var blockers []string
	for _, goal := range goals {
		if goal.Status != StatusInProgress && goal.Status != StatusDelivered {
			continue
		}
		for _, dependency := range goal.DependsOn {
			prerequisite, exists := goals[dependency]
			if !exists || prerequisite.Status != StatusDelivered {
				blockers = append(blockers, fmt.Sprintf("%s: %s status requires delivered dependency %s", goal.ID, goal.Status, dependency))
			}
		}
	}
	return blockers
}

func validateReleaseBoundary(goals map[string]*Goal) []string {
	var blockers []string
	for id, goal := range goals {
		if id == "G25" || id == "G26" {
			if goal.ReleaseTrack != "post_1_0" {
				blockers = append(blockers, id+": releaseTrack must be post_1_0")
			}
			continue
		}
		if goal.ReleaseTrack != "" {
			blockers = append(blockers, id+": only G25 and G26 may declare a releaseTrack")
		}
	}

	requiredTargets := map[string][]string{
		"G24": {"independent_provider"},
		"G27": {"independent_provider"},
		"G25": {"independent_provider", "region_primary", "region_secondary"},
		"G26": {"independent_provider", "federation_provider_a", "federation_provider_b"},
	}
	for id, expected := range requiredTargets {
		goal, exists := goals[id]
		if !exists {
			continue
		}
		for _, target := range expected {
			if !contains(goal.DeploymentTargets, target) {
				blockers = append(blockers, fmt.Sprintf("%s: deployment targets must include %s", id, target))
			}
		}
	}
	return blockers
}

func dependencyCycles(goals map[string]*Goal) []string {
	const (
		unvisited = iota
		visiting
		visited
	)
	state := make(map[string]int, len(goals))
	var blockers []string
	var visit func(string)
	visit = func(id string) {
		switch state[id] {
		case visiting:
			blockers = append(blockers, "dependency cycle detected at "+id)
			return
		case visited:
			return
		}
		state[id] = visiting
		for _, dependency := range goals[id].DependsOn {
			if _, exists := goals[dependency]; exists {
				visit(dependency)
			}
		}
		state[id] = visited
	}
	for id := range goals {
		visit(id)
	}
	return blockers
}

func validateInvariants(invariants []string) []string {
	var blockers []string
	if duplicates := duplicateValues(invariants); len(duplicates) != 0 {
		blockers = append(blockers, "duplicate invariants: "+strings.Join(duplicates, ", "))
	}
	for _, required := range requiredInvariants {
		if !contains(invariants, required) {
			blockers = append(blockers, "missing required invariant: "+required)
		}
	}
	return blockers
}

func (r *Roadmap) goalIndex() map[string]*Goal {
	goals := make(map[string]*Goal, len(r.Spec.DeliveryOrder))
	for index := range r.Spec.DeliveryOrder {
		goals[r.Spec.DeliveryOrder[index].ID] = &r.Spec.DeliveryOrder[index]
	}
	return goals
}

func headingGoalID(body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(fields) != 0 {
			return fields[0]
		}
		return ""
	}
	return ""
}

func allowedTransition(current, target Status) bool {
	switch current {
	case StatusNotStarted:
		return target == StatusInProgress || target == StatusBlocked
	case StatusBlocked:
		return target == StatusNotStarted || target == StatusInProgress
	case StatusInProgress:
		return target == StatusBlocked || target == StatusDelivered
	case StatusDelivered:
		return false
	default:
		return false
	}
}

func validStatus(status Status) bool {
	switch status {
	case StatusNotStarted, StatusInProgress, StatusBlocked, StatusDelivered:
		return true
	default:
		return false
	}
}

func duplicateValues(values []string) []string {
	seen := make(map[string]bool, len(values))
	duplicates := make(map[string]bool)
	for _, value := range values {
		if seen[value] {
			duplicates[value] = true
		}
		seen[value] = true
	}
	result := make([]string, 0, len(duplicates))
	for value := range duplicates {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func contains(values []string, target string) bool {
	return slices.Contains(values, target)
}
