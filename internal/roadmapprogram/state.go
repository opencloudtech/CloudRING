// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package roadmapprogram

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

var goalStateFilePattern = regexp.MustCompile(`^G[0-9]{2}\.json$`)

type schemaShape struct {
	required    []string
	properties  []string
	definitions []string
}

var stateSchemaShape = schemaShape{
	required: []string{
		"goal", "status", "requirements", "requirementResults", "updatedAt", "repositories",
		"artifacts", "deployments", "blockers", "rollbackBoundary", "predecessorRegression",
		"releaseManifest", "verdict",
	},
	properties: []string{
		"goal", "status", "requirements", "requirementResults", "updatedAt", "repositories",
		"artifacts", "deployments", "blockers", "rollbackBoundary", "predecessorRegression",
		"releaseManifest", "verdict",
	},
	definitions: []string{"digest", "evidenceRef", "repositoryProof", "requirementResult", "deliveredRequirementResult", "deploymentProof"},
}

var evidenceSchemaShape = schemaShape{
	required: []string{
		"goal", "requirement", "sourceSha", "releaseManifest", "observedAt", "expiresAt",
		"environment", "verdict", "proof", "redaction", "cleanup", "attestation",
	},
	properties: []string{
		"goal", "requirement", "sourceSha", "releaseManifest", "observedAt", "expiresAt",
		"environment", "verdict", "proof", "measurement", "redaction", "cleanup", "attestation",
	},
	definitions: []string{"digest", "evidenceRef"},
}

type evidenceReference struct {
	Digest         string `json:"digest"`
	Locator        string `json:"locator"`
	RetentionUntil string `json:"retentionUntil"`
}

type repositoryProof struct {
	Main   *string `json:"main"`
	Checks string  `json:"checks"`
	Pin    *string `json:"pin"`
}

type requirementResult struct {
	ID               string              `json:"id"`
	Applicability    string              `json:"applicability"`
	Evidence         []evidenceReference `json:"evidence"`
	ApprovalEvidence *evidenceReference  `json:"approvalEvidence"`
	Verdict          string              `json:"verdict"`
}

type deploymentProof struct {
	Target                 string              `json:"target"`
	EnvironmentFingerprint string              `json:"environmentFingerprint"`
	Profile                evidenceReference   `json:"profile"`
	GitOpsRevision         *string             `json:"gitOpsRevision"`
	Evidence               []evidenceReference `json:"evidence"`
	Cleanup                string              `json:"cleanup"`
	Verdict                string              `json:"verdict"`
}

type stateRecord struct {
	Goal               string              `json:"goal"`
	Status             Status              `json:"status"`
	Requirements       []string            `json:"requirements"`
	RequirementResults []requirementResult `json:"requirementResults"`
	Repositories       struct {
		Public    repositoryProof `json:"public"`
		Reference repositoryProof `json:"reference"`
		Provider  repositoryProof `json:"provider"`
	} `json:"repositories"`
	Artifacts             []evidenceReference `json:"artifacts"`
	Deployments           []deploymentProof   `json:"deployments"`
	Blockers              []string            `json:"blockers"`
	RollbackBoundary      *string             `json:"rollbackBoundary"`
	PredecessorRegression *evidenceReference  `json:"predecessorRegression"`
	ReleaseManifest       *evidenceReference  `json:"releaseManifest"`
	Verdict               string              `json:"verdict"`
}

func compileRoadmapSchema(root *os.Root, name string, shape schemaShape) (*jsonschema.Schema, error) {
	data, err := readRegular(root, name)
	if err != nil {
		return nil, err
	}
	document, err := decodeStrictJSON(data)
	if err != nil {
		return nil, fmt.Errorf("must be strict JSON: %w", err)
	}
	if err := validateSchemaShape(document, shape); err != nil {
		return nil, err
	}
	if err := validateLocalSchemaReferences(document); err != nil {
		return nil, err
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	const resource = "https://cloudring.org/schemas/roadmap-verifier-input.json"
	if err := compiler.AddResource(resource, document); err != nil {
		return nil, fmt.Errorf("register JSON Schema: %w", err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		return nil, fmt.Errorf("compile JSON Schema: %w", err)
	}
	return schema, nil
}

func validateLocalSchemaReferences(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "$ref" || key == "$dynamicRef" || key == "$recursiveRef" {
				reference, ok := child.(string)
				if !ok || (reference != "#" && !strings.HasPrefix(reference, "#/")) {
					return errors.New("JSON Schema references must be local fragments")
				}
			}
			if err := validateLocalSchemaReferences(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := validateLocalSchemaReferences(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSchemaShape(document any, shape schemaShape) error {
	object, ok := document.(map[string]any)
	if !ok {
		return errors.New("JSON Schema root must be an object")
	}
	if object["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		return errors.New("JSON Schema must declare draft 2020-12")
	}
	if object["type"] != "object" || object["additionalProperties"] != false {
		return errors.New("JSON Schema must define a closed object")
	}
	required, ok := stringSet(object["required"])
	if !ok {
		return errors.New("JSON Schema required must be an array of unique strings")
	}
	properties, ok := object["properties"].(map[string]any)
	if !ok {
		return errors.New("JSON Schema properties must be an object")
	}
	definitions, ok := object["$defs"].(map[string]any)
	if !ok {
		return errors.New("JSON Schema $defs must be an object")
	}
	for _, name := range shape.required {
		if !required[name] {
			return fmt.Errorf("JSON Schema must require %s", name)
		}
	}
	for _, name := range shape.properties {
		if _, ok := properties[name].(map[string]any); !ok {
			return fmt.Errorf("JSON Schema property %s must be a schema object", name)
		}
	}
	for _, name := range shape.definitions {
		if _, ok := definitions[name].(map[string]any); !ok {
			return fmt.Errorf("JSON Schema definition %s must be a schema object", name)
		}
	}
	if conditional, ok := object["allOf"].([]any); !ok || len(conditional) == 0 {
		return errors.New("JSON Schema must define conditional semantic checks")
	}
	return nil
}

func stringSet(value any) (map[string]bool, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make(map[string]bool, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok || text == "" || result[text] {
			return nil, false
		}
		result[text] = true
	}
	return result, true
}

// decodeStrictJSON preserves number precision, rejects trailing values, and
// rejects duplicate object keys at every nesting depth.
func decodeStrictJSON(data []byte) (any, error) {
	if len(data) == 0 || len(data) > maxRoadmapFileBytes {
		return nil, errors.New("JSON must be a non-empty bounded document")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("unexpected trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

func decodeJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key must be a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON object key %q", key)
			}
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, errors.New("unterminated JSON object")
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, errors.New("unterminated JSON array")
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func validateStateRecords(
	root *os.Root,
	roadmap *Roadmap,
	stateSchema *jsonschema.Schema,
	evidenceSchema *jsonschema.Schema,
	options ValidationOptions,
) []string {
	records, blockers := loadStateRecords(root, roadmap, stateSchema)
	resolver := newResolverSession(options)
	for index := range roadmap.Spec.DeliveryOrder {
		goal := &roadmap.Spec.DeliveryOrder[index]
		record, exists := records[goal.ID]
		if goal.Status == StatusInProgress || goal.Status == StatusBlocked || goal.Status == StatusDelivered {
			if !exists {
				blockers = append(blockers, fmt.Sprintf("%s: %s status requires state/%s.json", goal.ID, goal.Status, goal.ID))
				continue
			}
		}
		if !exists {
			continue
		}
		blockers = append(blockers, validateStateRecord(
			goal,
			record,
			roadmap.Spec.DefaultDeploymentTargets,
			roadmap.goalIndex(),
			evidenceSchema,
			resolver,
		)...)
	}
	return blockers
}

func loadStateRecords(root *os.Root, roadmap *Roadmap, schema *jsonschema.Schema) (map[string]*stateRecord, []string) {
	records := make(map[string]*stateRecord)
	info, err := root.Lstat("state")
	if err != nil {
		if os.IsNotExist(err) {
			return records, nil
		}
		return records, []string{"state: cannot inspect state directory"}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return records, []string{"state: must be an exact directory below the roadmap root"}
	}
	directory, err := root.Open("state")
	if err != nil {
		return records, []string{"state: cannot open state directory"}
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return records, []string{"state: cannot enumerate state directory"}
	}
	slices.SortFunc(entries, func(left, right os.DirEntry) int { return strings.Compare(left.Name(), right.Name()) })

	goals := roadmap.goalIndex()
	var blockers []string
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join("state", name)
		if name == "README.md" {
			if _, err := readRegular(root, path); err != nil {
				blockers = append(blockers, "state/README.md: "+err.Error())
			}
			continue
		}
		if !goalStateFilePattern.MatchString(name) {
			blockers = append(blockers, fmt.Sprintf("state/%s: unexpected state directory entry", name))
			continue
		}
		data, err := readRegular(root, path)
		if err != nil {
			blockers = append(blockers, fmt.Sprintf("state/%s: %v", name, err))
			continue
		}
		document, err := decodeStrictJSON(data)
		if err != nil {
			blockers = append(blockers, fmt.Sprintf("state/%s: invalid strict JSON: %v", name, err))
			continue
		}
		if err := schema.Validate(document); err != nil {
			blockers = append(blockers, fmt.Sprintf("state/%s: does not satisfy state schema: %v", name, err))
			continue
		}
		var record stateRecord
		if err := json.Unmarshal(data, &record); err != nil {
			blockers = append(blockers, fmt.Sprintf("state/%s: cannot decode validated state", name))
			continue
		}
		expectedGoal := strings.TrimSuffix(name, ".json")
		if record.Goal != expectedGoal {
			blockers = append(blockers, fmt.Sprintf("state/%s: goal must be %s", name, expectedGoal))
			continue
		}
		if _, exists := goals[record.Goal]; !exists {
			blockers = append(blockers, fmt.Sprintf("state/%s: goal is not in deliveryOrder", name))
			continue
		}
		records[record.Goal] = &record
	}
	return records, blockers
}

func validateStateRecord(
	goal *Goal,
	record *stateRecord,
	defaultTargets []string,
	goals map[string]*Goal,
	evidenceSchema *jsonschema.Schema,
	resolver *resolverSession,
) []string {
	var blockers []string
	if record.Status != goal.Status {
		blockers = append(blockers, fmt.Sprintf("%s: roadmap status %s does not match state status %s", goal.ID, goal.Status, record.Status))
	}
	if !slices.Equal(record.Requirements, goal.RequirementIDs) {
		blockers = append(blockers, fmt.Sprintf("%s: state requirements must exactly match roadmap requirementIds", goal.ID))
	}
	blockers = append(blockers, validateStateEvidence(goal, record, evidenceSchema, resolver)...)
	if record.Status != StatusDelivered {
		return blockers
	}
	for _, dependency := range goal.DependsOn {
		if prerequisite, exists := goals[dependency]; !exists || prerequisite.Status != StatusDelivered {
			blockers = append(blockers, fmt.Sprintf("%s: delivered state requires delivered dependency %s", goal.ID, dependency))
		}
	}
	publicSHA := record.Repositories.Public.Main
	if publicSHA == nil {
		blockers = append(blockers, goal.ID+": delivered state requires an exact accepted public SHA")
	} else {
		for label, downstream := range map[string]repositoryProof{
			"reference": record.Repositories.Reference,
			"provider":  record.Repositories.Provider,
		} {
			if downstream.Main == nil {
				blockers = append(blockers, fmt.Sprintf("%s: delivered state requires an exact accepted %s SHA", goal.ID, label))
			}
			if downstream.Pin == nil || *downstream.Pin != *publicSHA {
				blockers = append(blockers, fmt.Sprintf("%s: %s pin must equal the exact accepted public SHA", goal.ID, label))
			}
		}
	}

	resultIDs := make([]string, 0, len(record.RequirementResults))
	for _, result := range record.RequirementResults {
		resultIDs = append(resultIDs, result.ID)
	}
	slices.Sort(resultIDs)
	expectedRequirements := slices.Clone(goal.RequirementIDs)
	slices.Sort(expectedRequirements)
	if !slices.Equal(resultIDs, expectedRequirements) {
		blockers = append(blockers, goal.ID+": delivered requirementResults must exactly cover roadmap requirementIds")
	}
	if len(record.Artifacts) == 0 || record.ReleaseManifest == nil {
		blockers = append(blockers, goal.ID+": delivered state requires artifact and release-manifest proof")
	}
	if record.RollbackBoundary == nil || strings.TrimSpace(*record.RollbackBoundary) == "" {
		blockers = append(blockers, goal.ID+": delivered state requires rollback proof")
	}
	if goal.ID != "G00" && record.PredecessorRegression == nil {
		blockers = append(blockers, goal.ID+": delivered state requires predecessor regression evidence")
	}

	targets := goal.DeploymentTargets
	if len(targets) == 0 {
		targets = defaultTargets
	}
	actualTargets := make([]string, 0, len(record.Deployments))
	seenTargets := make(map[string]bool, len(record.Deployments))
	for _, deployment := range record.Deployments {
		actualTargets = append(actualTargets, deployment.Target)
		if seenTargets[deployment.Target] {
			blockers = append(blockers, fmt.Sprintf("%s: duplicate delivered deployment target %s", goal.ID, deployment.Target))
		}
		seenTargets[deployment.Target] = true
		if len(deployment.Evidence) == 0 || (deployment.Cleanup != "complete" && deployment.Cleanup != "not_applicable") {
			blockers = append(blockers, fmt.Sprintf("%s: deployment %s requires evidence and cleanup proof", goal.ID, deployment.Target))
		}
		if deployment.Target == "public_clean_room" && deployment.Cleanup != "complete" {
			blockers = append(blockers, goal.ID+": public clean-room deployment requires completed cleanup proof")
		}
	}
	blockers = append(blockers, validateIndependentDeploymentFingerprints(goal.ID, record.Deployments)...)
	slices.Sort(actualTargets)
	expectedTargets := slices.Clone(targets)
	slices.Sort(expectedTargets)
	if !slices.Equal(actualTargets, expectedTargets) {
		blockers = append(blockers, fmt.Sprintf("%s: delivered deployments must exactly match %v", goal.ID, expectedTargets))
	}
	if record.Repositories.Reference.Main != nil {
		for _, deployment := range record.Deployments {
			if deployment.Target == "hub" && (deployment.GitOpsRevision == nil || *deployment.GitOpsRevision != *record.Repositories.Reference.Main) {
				blockers = append(blockers, goal.ID+": hub GitOps revision must equal the exact accepted reference SHA")
			}
		}
	}
	if record.Repositories.Provider.Main != nil {
		for _, deployment := range record.Deployments {
			if deployment.Target == "independent_provider" && (deployment.GitOpsRevision == nil || *deployment.GitOpsRevision != *record.Repositories.Provider.Main) {
				blockers = append(blockers, goal.ID+": independent provider GitOps revision must equal the exact accepted provider SHA")
			}
		}
	}
	return blockers
}

func validateIndependentDeploymentFingerprints(goalID string, deployments []deploymentProof) []string {
	fingerprints := make(map[string]string, len(deployments))
	for _, deployment := range deployments {
		if _, exists := fingerprints[deployment.Target]; !exists {
			fingerprints[deployment.Target] = deployment.EnvironmentFingerprint
		}
	}

	pairs := [][2]string{
		{"region_primary", "region_secondary"},
		{"federation_provider_a", "federation_provider_b"},
	}
	var blockers []string
	for _, pair := range pairs {
		left, leftExists := fingerprints[pair[0]]
		right, rightExists := fingerprints[pair[1]]
		if !leftExists || !rightExists {
			continue
		}
		if left == "" || right == "" {
			blockers = append(blockers, fmt.Sprintf(
				"%s: %s and %s require non-empty environment fingerprints",
				goalID,
				pair[0],
				pair[1],
			))
			continue
		}
		if left == right {
			blockers = append(blockers, fmt.Sprintf(
				"%s: %s and %s must use distinct environment fingerprints",
				goalID,
				pair[0],
				pair[1],
			))
		}
	}
	return blockers
}

func validateStateEvidence(
	goal *Goal,
	record *stateRecord,
	evidenceSchema *jsonschema.Schema,
	resolver *resolverSession,
) []string {
	var blockers []string
	maxAge := time.Duration(0)
	if resolver.resolver != nil && stateHasEvidenceReferences(record) {
		var err error
		maxAge, err = resolver.freshnessCeiling(goal.ID)
		if err != nil {
			return []string{err.Error()}
		}
	}
	publicSHA := ""
	if record.Repositories.Public.Main != nil {
		publicSHA = *record.Repositories.Public.Main
	}
	base := evidenceExpectation{
		goal:            goal.ID,
		requirements:    goal.RequirementIDs,
		sourceSHA:       publicSHA,
		releaseManifest: record.ReleaseManifest,
		requirePass:     record.Status == StatusDelivered,
		maxAge:          maxAge,
	}

	for index, reference := range record.Artifacts {
		if _, err := resolver.resolveReference(reference, fmt.Sprintf("%s: artifact[%d]", goal.ID, index), false); err != nil {
			blockers = append(blockers, err.Error())
		}
	}
	if record.ReleaseManifest != nil {
		if _, err := resolver.resolveReference(*record.ReleaseManifest, goal.ID+": release manifest", false); err != nil {
			blockers = append(blockers, err.Error())
		}
	}
	if record.PredecessorRegression != nil {
		if err := resolver.validateEvidenceRecord(
			*record.PredecessorRegression,
			goal.ID+": predecessor regression",
			evidenceSchema,
			base,
		); err != nil {
			blockers = append(blockers, err.Error())
		}
	}

	for resultIndex, result := range record.RequirementResults {
		expectation := base
		expectation.requirement = result.ID
		for evidenceIndex, reference := range result.Evidence {
			label := fmt.Sprintf("%s: requirementResults[%d].evidence[%d]", goal.ID, resultIndex, evidenceIndex)
			if err := resolver.validateEvidenceRecord(reference, label, evidenceSchema, expectation); err != nil {
				blockers = append(blockers, err.Error())
			}
		}
		if result.ApprovalEvidence != nil {
			label := fmt.Sprintf("%s: requirementResults[%d].approvalEvidence", goal.ID, resultIndex)
			if err := resolver.validateEvidenceRecord(*result.ApprovalEvidence, label, evidenceSchema, expectation); err != nil {
				blockers = append(blockers, err.Error())
			}
		}
	}

	for deploymentIndex, deployment := range record.Deployments {
		profileLabel := fmt.Sprintf("%s: deployments[%d].profile", goal.ID, deploymentIndex)
		if _, err := resolver.resolveReference(deployment.Profile, profileLabel, false); err != nil {
			blockers = append(blockers, err.Error())
		}
		expectation := base
		expectation.target = deployment.Target
		expectation.fingerprint = deployment.EnvironmentFingerprint
		expectation.profile = &deployment.Profile
		expectation.gitOpsRevision = deployment.GitOpsRevision
		for evidenceIndex, reference := range deployment.Evidence {
			label := fmt.Sprintf("%s: deployments[%d].evidence[%d]", goal.ID, deploymentIndex, evidenceIndex)
			if err := resolver.validateEvidenceRecord(reference, label, evidenceSchema, expectation); err != nil {
				blockers = append(blockers, err.Error())
			}
		}
	}
	return blockers
}

func stateHasEvidenceReferences(record *stateRecord) bool {
	if len(record.Artifacts) != 0 || record.ReleaseManifest != nil || record.PredecessorRegression != nil {
		return true
	}
	for _, result := range record.RequirementResults {
		if len(result.Evidence) != 0 || result.ApprovalEvidence != nil {
			return true
		}
	}
	for _, deployment := range record.Deployments {
		// A schema-valid deployment always has a profile reference.
		if deployment.Profile.Locator != "" || len(deployment.Evidence) != 0 {
			return true
		}
	}
	return false
}
