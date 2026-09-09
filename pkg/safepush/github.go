// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package safepush

import (
	"context"
	"crypto/sha1" // #nosec G505 -- Git object identifiers, not signatures.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

// Fixed error categories never expose credentials, remote response bodies,
// repository contents, URLs, or candidate-controlled names.
var (
	ErrGitHubPending   = errors.New("safepush: required GitHub runs are pending")
	ErrGitHubAPI       = errors.New("safepush: GitHub API read failed")
	ErrGitHubCandidate = errors.New("safepush: invalid GitHub candidate")
	ErrGitHubState     = errors.New("safepush: GitHub candidate or target state changed")
	ErrGitHubSource    = errors.New("safepush: GitHub workflow source is not trusted")
	ErrGitHubRun       = errors.New("safepush: GitHub run provenance is invalid")
)

const (
	githubAPIOrigin = "https://api.github.com"
	githubActionsID = int64(15368)
	githubPageSize  = 100
	githubListLimit = 1000
)

type githubAPI struct {
	client      *http.Client
	bearerValue string
	repo        string
}

type githubRepository struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Archived bool   `json:"archived"`
	Disabled bool   `json:"disabled"`
}

type githubRef struct {
	Ref  string           `json:"ref"`
	SHA  string           `json:"sha"`
	Repo githubRepository `json:"repo"`
}

type githubPullRequest struct {
	ID     int64     `json:"id"`
	Number int       `json:"number"`
	State  string    `json:"state"`
	Draft  bool      `json:"draft"`
	Merged bool      `json:"merged"`
	Head   githubRef `json:"head"`
	Base   githubRef `json:"base"`
}

type githubBranch struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
	Commit    struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

type githubTreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type githubTree struct {
	SHA       string            `json:"sha"`
	Truncated *bool             `json:"truncated"`
	Tree      []githubTreeEntry `json:"tree"`
}

type githubWorkflow struct {
	ID    int64  `json:"id"`
	Path  string `json:"path"`
	State string `json:"state"`
}

type githubRun struct {
	ID                  int64             `json:"id"`
	WorkflowID          int64             `json:"workflow_id"`
	RunNumber           int64             `json:"run_number"`
	RunAttempt          int               `json:"run_attempt"`
	CheckSuiteID        int64             `json:"check_suite_id"`
	Path                string            `json:"path"`
	Event               string            `json:"event"`
	HeadSHA             string            `json:"head_sha"`
	HeadBranch          string            `json:"head_branch"`
	Status              string            `json:"status"`
	Conclusion          string            `json:"conclusion"`
	Repository          githubRepository  `json:"repository"`
	HeadRepository      githubRepository  `json:"head_repository"`
	ReferencedWorkflows []json.RawMessage `json:"referenced_workflows"`
	PullRequests        []githubRunPR     `json:"pull_requests"`
}

type githubRunPR struct {
	ID     int64     `json:"id"`
	Number int       `json:"number"`
	URL    string    `json:"url"`
	Head   githubRef `json:"head"`
	Base   githubRef `json:"base"`
}

type githubStep struct {
	Name       string `json:"name"`
	Number     int    `json:"number"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

type githubJob struct {
	ID          int64        `json:"id"`
	RunID       int64        `json:"run_id"`
	RunAttempt  int          `json:"run_attempt"`
	HeadSHA     string       `json:"head_sha"`
	HeadBranch  string       `json:"head_branch"`
	Name        string       `json:"name"`
	Status      string       `json:"status"`
	Conclusion  string       `json:"conclusion"`
	CheckRunURL string       `json:"check_run_url"`
	Steps       []githubStep `json:"steps"`
}

type githubCheckRun struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	CheckSuite struct {
		ID int64 `json:"id"`
	} `json:"check_suite"`
	App struct {
		ID   int64  `json:"id"`
		Slug string `json:"slug"`
	} `json:"app"`
}

// ReadGitHubPolicy reads the accepted base's regular policy blob without a
// checkout or contents-API symlink dereference. VerifyGitHub subsequently proves
// that this base is still the current protected target. The caller must obtain
// repository/baseSHA from its trusted workflow event, not candidate output.
func ReadGitHubPolicy(ctx context.Context, client *http.Client, token, repository, baseSHA string) (GitHubPolicy, error) {
	if !repositoryName.MatchString(repository) || strings.HasSuffix(repository, "/.") ||
		strings.HasSuffix(repository, "/..") || !validHeadSHA(baseSHA) {
		return GitHubPolicy{}, ErrPolicy
	}
	api, err := newGitHubAPI(client, token, repository)
	if err != nil {
		return GitHubPolicy{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var repo githubRepository
	if err = api.get(ctx, "", nil, &repo); err != nil {
		return GitHubPolicy{}, err
	}
	if repo.ID <= 0 || repo.FullName != repository || repo.Archived || repo.Disabled {
		return GitHubPolicy{}, ErrGitHubState
	}
	tree, err := api.readTree(ctx, baseSHA)
	if err != nil {
		return GitHubPolicy{}, err
	}
	entry, exists := tree[".github/safepush.json"]
	if !exists || entry.Type != "blob" || entry.Mode != "100644" {
		return GitHubPolicy{}, ErrGitHubSource
	}
	contents, err := api.readGitBlob(ctx, entry, strictjson.MaxDocumentBytes)
	if err != nil {
		return GitHubPolicy{}, err
	}
	policy, err := DecodeGitHubPolicy(contents)
	if err != nil {
		return GitHubPolicy{}, ErrPolicy
	}
	if policy.Repository != repo.FullName || policy.RepositoryID != repo.ID {
		return GitHubPolicy{}, ErrGitHubSource
	}
	if ctx.Err() != nil {
		return GitHubPolicy{}, ErrGitHubAPI
	}
	return policy, nil
}

// VerifyGitHub verifies native PR/run/job provenance using the accepted policy.
// It executes no candidate code. Both required and excluded workflow files, and
// .github/scripts, must match the accepted base. This deliberately does not
// authenticate generated dynamic workflows or reusable workflow chains.
//
// Base must be an ancestor of head. With unchanged workflow sources this avoids
// claiming a stale PR test-merge tested newer candidate bytes. Native required
// reviews and branch rules remain necessary: these API reads are not an atomic
// ref-update transaction and do not prove the semantic adequacy of tests.
func VerifyGitHub(ctx context.Context, client *http.Client, token string, policy GitHubPolicy, candidate GitHubCandidate) error {
	if err := ValidateGitHubPolicy(policy); err != nil {
		return err
	}
	if ValidateGitHubCandidate(policy.Repository, candidate) != nil {
		return ErrGitHubCandidate
	}
	api, err := newGitHubAPI(client, token, policy.Repository)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var repo githubRepository
	if err = api.get(ctx, "", nil, &repo); err != nil {
		return err
	}
	if repo.ID != policy.RepositoryID || repo.FullName != policy.Repository || repo.Archived || repo.Disabled {
		return ErrGitHubState
	}
	pr, err := api.readCandidate(ctx, policy, candidate)
	if err != nil {
		return err
	}
	if err = api.requireBaseAncestor(ctx, candidate); err != nil {
		return err
	}
	baseTree, err := api.readTree(ctx, candidate.BaseSHA)
	if err != nil {
		return err
	}
	headTree, err := api.readTree(ctx, candidate.HeadSHA)
	if err != nil {
		return err
	}
	if err = verifyGitHubSources(policy, baseTree, headTree); err != nil {
		return err
	}
	for _, workflow := range policy.Workflows {
		contents, readErr := api.readGitBlob(ctx, baseTree[workflow.Path], maxWorkflowSourceBytes)
		if readErr != nil {
			return readErr
		}
		if err = verifyWorkflowSource(contents); err != nil {
			return err
		}
	}
	workflows, err := api.readWorkflows(ctx, policy)
	if err != nil {
		return err
	}
	runs, err := api.selectRuns(ctx, policy, pr, workflows)
	if err != nil {
		return err
	}
	var required []CheckIdentity
	var observations []CheckObservation
	for _, workflow := range policy.Workflows {
		source := workflow.Path + "@" + baseTree[workflow.Path].SHA
		for _, job := range workflow.Jobs {
			required = append(required, CheckIdentity{Source: source, Job: job})
		}
		items, collectErr := api.readObservations(ctx, runs[workflow.Path], source)
		if collectErr != nil {
			return collectErr
		}
		observations = append(observations, items...)
	}
	if err = VerifyChecks(candidate.HeadSHA, required, observations); err != nil {
		return err
	}
	finalWorkflows, err := api.readWorkflows(ctx, policy)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(workflows, finalWorkflows) {
		return ErrGitHubState
	}
	finalRuns, err := api.selectRuns(ctx, policy, pr, finalWorkflows)
	if err != nil {
		// A newly selected run or attempt invalidates this collection, even if
		// it is pending. A new admission attempt must collect a new snapshot.
		if errors.Is(err, ErrGitHubPending) {
			return ErrGitHubState
		}
		return err
	}
	if !reflect.DeepEqual(runs, finalRuns) {
		return ErrGitHubState
	}
	for _, workflow := range policy.Workflows {
		run := runs[workflow.Path]
		var finalRun githubRun
		if err = api.get(ctx, "/actions/runs/"+strconv.FormatInt(run.ID, 10), nil, &finalRun); err != nil {
			return err
		}
		if !reflect.DeepEqual(run, finalRun) {
			return ErrGitHubState
		}
	}
	finalPR, err := api.readCandidate(ctx, policy, candidate)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(pr, finalPR) {
		return ErrGitHubState
	}
	if ctx.Err() != nil {
		return ErrGitHubAPI
	}
	return nil
}

func newGitHubAPI(client *http.Client, token, repository string) (*githubAPI, error) {
	if token == "" {
		return nil, ErrGitHubAPI
	}
	for _, value := range token {
		if value <= 0x20 || value >= 0x7f {
			return nil, ErrGitHubAPI
		}
	}
	if client == nil {
		client = http.DefaultClient
	}
	copyClient := *client
	copyClient.Jar = nil
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if copyClient.Timeout == 0 || copyClient.Timeout > 30*time.Second {
		copyClient.Timeout = 30 * time.Second
	}
	return &githubAPI{client: &copyClient, bearerValue: token, repo: repository}, nil
}

func (api *githubAPI) get(ctx context.Context, suffix string, query url.Values, destination any) error {
	u := url.URL{Scheme: "https", Host: "api.github.com", Path: "/repos/" + api.repo + suffix, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ErrGitHubAPI
	}
	req.Header.Set("Authorization", "Bearer "+api.bearerValue)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "CloudRING-SafePush")
	resp, err := api.client.Do(req)
	if err != nil {
		return ErrGitHubAPI
	}
	defer resp.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || mediaErr != nil ||
		(mediaType != "application/json" && mediaType != "application/vnd.github+json") ||
		resp.ContentLength > strictjson.MaxDocumentBytes {
		return ErrGitHubAPI
	}
	data, err := strictjson.Read(resp.Body)
	if err != nil || strictjson.Decode(data, destination) != nil {
		return ErrGitHubAPI
	}
	return nil
}

func githubList[T any](ctx context.Context, api *githubAPI, suffix, key string, filters url.Values) ([]T, error) {
	var result []T
	declared := -1
	for page := 1; page <= githubListLimit/githubPageSize; page++ {
		query := make(url.Values)
		for name, values := range filters {
			query[name] = append([]string(nil), values...)
		}
		query.Set("per_page", strconv.Itoa(githubPageSize))
		query.Set("page", strconv.Itoa(page))
		var envelope map[string]json.RawMessage
		if err := api.get(ctx, suffix, query, &envelope); err != nil {
			return nil, err
		}
		var total int
		if raw := envelope["total_count"]; len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &total) != nil || total < 0 || total > githubListLimit {
			return nil, ErrGitHubAPI
		}
		for _, flag := range []string{"truncated", "incomplete_results"} {
			if raw, found := envelope[flag]; found && string(raw) != "false" {
				return nil, ErrGitHubAPI
			}
		}
		if declared != -1 && declared != total {
			return nil, ErrGitHubState
		}
		declared = total
		var items []T
		if json.Unmarshal(envelope[key], &items) != nil || items == nil {
			return nil, ErrGitHubAPI
		}
		if len(items) != min(githubPageSize, total-len(result)) {
			return nil, ErrGitHubAPI
		}
		result = append(result, items...)
		if len(result) == total {
			return result, nil
		}
	}
	return nil, ErrGitHubAPI
}

func (api *githubAPI) readCandidate(ctx context.Context, policy GitHubPolicy, candidate GitHubCandidate) (githubPullRequest, error) {
	var pr githubPullRequest
	if err := api.get(ctx, "/pulls/"+strconv.Itoa(candidate.PullRequest), nil, &pr); err != nil {
		return pr, err
	}
	if pr.ID <= 0 || pr.Number != candidate.PullRequest || pr.State != "open" || pr.Draft || pr.Merged ||
		pr.Head.SHA != candidate.HeadSHA || !validJobName(pr.Head.Ref) || pr.Head.Repo.ID <= 0 ||
		!repositoryName.MatchString(pr.Head.Repo.FullName) ||
		pr.Base.SHA != candidate.BaseSHA || pr.Base.Ref != candidate.TargetBranch ||
		pr.Base.Repo.ID != policy.RepositoryID || pr.Base.Repo.FullName != policy.Repository {
		return pr, ErrGitHubState
	}
	var branch githubBranch
	if err := api.get(ctx, "/branches/"+candidate.TargetBranch, nil, &branch); err != nil {
		return pr, err
	}
	if branch.Name != candidate.TargetBranch || branch.Commit.SHA != candidate.BaseSHA || !branch.Protected {
		return pr, ErrGitHubState
	}
	return pr, nil
}

func (api *githubAPI) requireBaseAncestor(ctx context.Context, candidate GitHubCandidate) error {
	var comparison struct {
		Status   string `json:"status"`
		AheadBy  *int   `json:"ahead_by"`
		BehindBy *int   `json:"behind_by"`
		Base     struct {
			SHA string `json:"sha"`
		} `json:"base_commit"`
		MergeBase struct {
			SHA string `json:"sha"`
		} `json:"merge_base_commit"`
	}
	if err := api.get(ctx, "/compare/"+candidate.BaseSHA+"..."+candidate.HeadSHA, url.Values{"per_page": {"1"}}, &comparison); err != nil {
		return err
	}
	if comparison.Status != "ahead" || comparison.AheadBy == nil || *comparison.AheadBy <= 0 ||
		comparison.BehindBy == nil || *comparison.BehindBy != 0 ||
		comparison.Base.SHA != candidate.BaseSHA || comparison.MergeBase.SHA != candidate.BaseSHA {
		return ErrGitHubState
	}
	return nil
}

func (api *githubAPI) readTree(ctx context.Context, sha string) (map[string]githubTreeEntry, error) {
	var commit struct {
		SHA  string `json:"sha"`
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := api.get(ctx, "/git/commits/"+sha, nil, &commit); err != nil {
		return nil, err
	}
	if commit.SHA != sha || !validHeadSHA(commit.Tree.SHA) {
		return nil, ErrGitHubSource
	}
	var response githubTree
	if err := api.get(ctx, "/git/trees/"+commit.Tree.SHA, url.Values{"recursive": {"1"}}, &response); err != nil {
		return nil, err
	}
	if response.SHA != commit.Tree.SHA || response.Truncated == nil || *response.Truncated || response.Tree == nil {
		return nil, ErrGitHubSource
	}
	entries := make(map[string]githubTreeEntry, len(response.Tree))
	for _, entry := range response.Tree {
		if !validJobName(entry.Path) || !validHeadSHA(entry.SHA) {
			return nil, ErrGitHubSource
		}
		if _, duplicate := entries[entry.Path]; duplicate {
			return nil, ErrGitHubSource
		}
		entries[entry.Path] = entry
	}
	return entries, nil
}

func (api *githubAPI) readGitBlob(ctx context.Context, entry githubTreeEntry, limit int) ([]byte, error) {
	if entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755") ||
		!validHeadSHA(entry.SHA) || limit <= 0 || limit > strictjson.MaxDocumentBytes {
		return nil, ErrGitHubSource
	}
	var blob struct {
		SHA      string `json:"sha"`
		Encoding string `json:"encoding"`
		Size     *int   `json:"size"`
		Content  string `json:"content"`
	}
	if err := api.get(ctx, "/git/blobs/"+entry.SHA, nil, &blob); err != nil {
		return nil, err
	}
	if blob.SHA != entry.SHA || blob.Encoding != "base64" || blob.Size == nil || *blob.Size <= 0 || *blob.Size > limit {
		return nil, ErrGitHubSource
	}
	contents, err := base64.StdEncoding.DecodeString(blob.Content)
	if err != nil || len(contents) != *blob.Size || gitBlobID(contents, len(entry.SHA)) != entry.SHA {
		return nil, ErrGitHubSource
	}
	if ctx.Err() != nil {
		return nil, ErrGitHubAPI
	}
	return contents, nil
}

func verifyGitHubSources(policy GitHubPolicy, base, head map[string]githubTreeEntry) error {
	expected := make(map[string]bool)
	for _, workflow := range policy.Workflows {
		expected[workflow.Path] = true
	}
	for _, excluded := range policy.ExcludedWorkflows {
		expected[excluded] = true
	}
	guarded := func(entries map[string]githubTreeEntry) (map[string]githubTreeEntry, error) {
		result := make(map[string]githubTreeEntry)
		found := make(map[string]bool)
		for name, entry := range entries {
			if name == ".github/workflows" || strings.HasPrefix(name, ".github/workflows/") ||
				name == ".github/scripts" || strings.HasPrefix(name, ".github/scripts/") || name == ".github/workflow-policy.json" {
				if (entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755")) &&
					(entry.Type != "tree" || entry.Mode != "040000") {
					return nil, ErrGitHubSource
				}
				result[name] = entry
			}
			if strings.HasPrefix(name, ".github/workflows/") && entry.Type != "tree" &&
				(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
				if !validWorkflowPath(name) || !expected[name] {
					return nil, ErrGitHubSource
				}
				found[name] = true
			}
		}
		if len(found) != len(expected) {
			return nil, ErrGitHubSource
		}
		return result, nil
	}
	trusted, err := guarded(base)
	if err != nil {
		return err
	}
	candidate, err := guarded(head)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(trusted, candidate) {
		return ErrGitHubSource
	}
	return nil
}

func (api *githubAPI) readWorkflows(ctx context.Context, policy GitHubPolicy) (map[string]githubWorkflow, error) {
	items, err := githubList[githubWorkflow](ctx, api, "/actions/workflows", "workflows", nil)
	if err != nil {
		return nil, err
	}
	expected := make(map[string]bool)
	for _, workflow := range policy.Workflows {
		expected[workflow.Path] = true
	}
	for _, excluded := range policy.ExcludedWorkflows {
		expected[excluded] = false
	}
	result := make(map[string]githubWorkflow)
	ids := make(map[int64]bool)
	for _, item := range items {
		if item.ID <= 0 || ids[item.ID] {
			return nil, ErrGitHubSource
		}
		ids[item.ID] = true
		if strings.HasPrefix(item.Path, "dynamic/") {
			continue // Native generated scanning remains a separate provider rule.
		}
		required, exists := expected[item.Path]
		if !exists {
			return nil, ErrGitHubSource
		}
		if _, duplicate := result[item.Path]; duplicate || (required && item.State != "active") {
			return nil, ErrGitHubSource
		}
		result[item.Path] = item
	}
	if len(result) != len(expected) {
		return nil, ErrGitHubSource
	}
	return result, nil
}

func (api *githubAPI) selectRuns(ctx context.Context, policy GitHubPolicy, pr githubPullRequest, workflows map[string]githubWorkflow) (map[string]githubRun, error) {
	items, err := githubList[githubRun](ctx, api, "/actions/runs", "workflow_runs", url.Values{"event": {"pull_request"}, "head_sha": {pr.Head.SHA}})
	if err != nil {
		return nil, err
	}
	result := make(map[string]githubRun)
	ids := make(map[int64]bool)
	requiredPaths := make(map[string]bool)
	requiredIDs := make(map[int64]bool)
	for _, workflow := range policy.Workflows {
		requiredPaths[workflow.Path] = true
		requiredIDs[workflows[workflow.Path].ID] = true
	}
	for _, item := range items {
		// Excluded release/verifier runs and provider-injected workflows cannot
		// satisfy a test identity. In particular do not wait on this gate itself.
		if !requiredPaths[item.Path] && !requiredIDs[item.WorkflowID] {
			continue
		}
		workflow, exists := workflows[item.Path]
		if !exists || item.ID <= 0 || ids[item.ID] || item.RunNumber <= 0 || item.RunAttempt <= 0 || item.CheckSuiteID <= 0 ||
			item.WorkflowID != workflow.ID || item.Event != "pull_request" ||
			item.HeadSHA != pr.Head.SHA || item.HeadBranch != pr.Head.Ref ||
			item.Repository.ID != policy.RepositoryID || item.Repository.FullName != policy.Repository ||
			item.HeadRepository.ID != pr.Head.Repo.ID || item.HeadRepository.FullName != pr.Head.Repo.FullName ||
			len(item.ReferencedWorkflows) != 0 || !api.runMatchesPR(item, pr) {
			return nil, ErrGitHubRun
		}
		ids[item.ID] = true
		prior, exists := result[item.Path]
		if exists && item.RunNumber == prior.RunNumber {
			return nil, ErrGitHubRun
		}
		if !exists || item.RunNumber > prior.RunNumber {
			result[item.Path] = item
		}
	}
	pending := false
	for _, workflow := range policy.Workflows {
		run, exists := result[workflow.Path]
		if !exists {
			pending = true
			continue
		}
		switch run.Status {
		case "completed":
			if run.Conclusion != "success" {
				return nil, ErrCheckNotSuccessful
			}
		case "queued", "in_progress", "waiting", "requested", "pending":
			pending = true
		default:
			return nil, ErrGitHubRun
		}
	}
	if pending {
		return nil, ErrGitHubPending
	}
	return result, nil
}

func (api *githubAPI) runMatchesPR(run githubRun, pr githubPullRequest) bool {
	// A head SHA can be reused by another PR or after retargeting. Do not treat
	// the run's head alone as an association with this exact PR/base snapshot.
	// Empty associations occur for closed or otherwise unavailable PRs; those
	// cannot provide the provenance needed for this open-PR admission.
	if len(run.PullRequests) != 1 {
		return false
	}
	linked := run.PullRequests[0]
	return linked.ID == pr.ID && linked.Number == pr.Number &&
		linked.URL == githubAPIOrigin+"/repos/"+api.repo+"/pulls/"+strconv.Itoa(pr.Number) &&
		linked.Head.SHA == pr.Head.SHA && linked.Head.Ref == pr.Head.Ref && linked.Head.Repo.ID == pr.Head.Repo.ID &&
		linked.Base.SHA == pr.Base.SHA && linked.Base.Ref == pr.Base.Ref && linked.Base.Repo.ID == pr.Base.Repo.ID
}

func (api *githubAPI) readObservations(ctx context.Context, run githubRun, source string) ([]CheckObservation, error) {
	suffix := fmt.Sprintf("/actions/runs/%d/attempts/%d/jobs", run.ID, run.RunAttempt)
	jobs, err := githubList[githubJob](ctx, api, suffix, "jobs", nil)
	if err != nil {
		return nil, err
	}
	checks, err := githubList[githubCheckRun](ctx, api, fmt.Sprintf("/check-suites/%d/check-runs", run.CheckSuiteID), "check_runs", url.Values{"filter": {"latest"}})
	if err != nil {
		return nil, err
	}
	checkByID := make(map[int64]githubCheckRun)
	for _, check := range checks {
		if check.ID <= 0 || checkByID[check.ID].ID != 0 || check.CheckSuite.ID != run.CheckSuiteID ||
			check.App.ID != githubActionsID || check.App.Slug != "github-actions" || check.HeadSHA != run.HeadSHA ||
			check.Status != "completed" || check.Conclusion != "success" {
			return nil, ErrGitHubRun
		}
		checkByID[check.ID] = check
	}
	var observations []CheckObservation
	jobIDs := make(map[int64]bool)
	usedChecks := make(map[int64]bool)
	for _, job := range jobs {
		if job.ID <= 0 || jobIDs[job.ID] || job.RunID != run.ID || job.RunAttempt != run.RunAttempt ||
			job.HeadSHA != run.HeadSHA || job.HeadBranch != run.HeadBranch || len(job.Steps) == 0 {
			return nil, ErrGitHubRun
		}
		jobIDs[job.ID] = true
		prefix := githubAPIOrigin + "/repos/" + api.repo + "/check-runs/"
		rawID, found := strings.CutPrefix(job.CheckRunURL, prefix)
		checkID, parseErr := strconv.ParseInt(rawID, 10, 64)
		if !found || parseErr != nil || checkID <= 0 || rawID != strconv.FormatInt(checkID, 10) || usedChecks[checkID] {
			return nil, ErrGitHubRun
		}
		check, exists := checkByID[checkID]
		if !exists || check.Name != job.Name {
			return nil, ErrGitHubRun
		}
		usedChecks[checkID] = true
		stepNumbers := make(map[int]bool)
		for _, step := range job.Steps {
			if step.Number <= 0 || stepNumbers[step.Number] || !validJobName(step.Name) || step.Status != "completed" || step.Conclusion != "success" {
				return nil, ErrGitHubRun
			}
			stepNumbers[step.Number] = true
		}
		observations = append(observations, CheckObservation{Check: CheckIdentity{Source: source, Job: job.Name}, HeadSHA: job.HeadSHA, Status: job.Status, Conclusion: job.Conclusion})
	}
	if len(usedChecks) != len(checkByID) {
		return nil, ErrGitHubRun
	}
	return observations, nil
}

func gitBlobID(contents []byte, length int) string {
	object := append([]byte(fmt.Sprintf("blob %d\x00", len(contents))), contents...)
	if length == 40 {
		digest := sha1.Sum(object) // #nosec G401 -- required Git object identifier.
		return hex.EncodeToString(digest[:])
	}
	digest := sha256.Sum256(object)
	return hex.EncodeToString(digest[:])
}
