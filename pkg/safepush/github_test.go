// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package safepush

import (
	"context"
	"crypto/sha1" // #nosec G505 -- synthetic Git object fixture identifiers.
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const (
	ghTestHead     = "1111111111111111111111111111111111111111"
	ghTestBase     = "2222222222222222222222222222222222222222"
	ghTestHeadTree = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ghTestBaseTree = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	ghTestBlob     = "e69e9a60e26d1cd37de67076728528819fec5844"
	ghTestOther    = "9999999999999999999999999999999999999999"
	ghTestPolicyID = "85b9611e54998ddb6ae044af1c6622072c9fa29a"
	ghTestPolicy   = `{"schemaVersion":"cloudring.safepush.github/v1","repository":"owner/repo","repositoryId":42,"workflows":[{"path":".github/workflows/ci.yml","jobs":["unit","race"]}],"excludedWorkflows":[".github/workflows/release.yml"]}`
	ghTestWorkflow = `name: CI
on: pull_request
jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - name: Run tests
        run: go test ./...
  race:
    runs-on: ubuntu-latest
    steps:
      - name: Run tests
        run: go test -race ./...
`
)

// These are HTTP JSON fixtures shaped from the provider API, with deliberately
// distinct commit, tree and blob IDs. The adapter always addresses the official
// HTTPS origin; only this test transport connects it to an isolated TLS server.
type githubHTTPSFixture struct {
	t         *testing.T
	client    *http.Client
	responses map[string]any
	mu        sync.Mutex
	counts    map[string]int
	requests  []string
	mutate    func(*http.Request, int, map[string]any)
	reply     func(http.ResponseWriter, *http.Request, int) bool
	policy    GitHubPolicy
	candidate GitHubCandidate
}

type githubFixtureTransport struct {
	t      *testing.T
	base   http.RoundTripper
	target *url.URL
}

func (transport githubFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != "api.github.com" || request.URL.User != nil {
		transport.t.Error("adapter attempted a non-official API origin")
		return nil, errors.New("unexpected test origin")
	}
	copyRequest := request.Clone(request.Context())
	copyURL := *request.URL
	copyURL.Host = transport.target.Host
	copyRequest.URL = &copyURL
	copyRequest.Host = transport.target.Host
	response, err := transport.base.RoundTrip(copyRequest)
	if response != nil {
		response.Request = request
	}
	return response, err
}

func newGitHubHTTPSFixture(t *testing.T) *githubHTTPSFixture {
	t.Helper()
	fixture := &githubHTTPSFixture{t: t, responses: make(map[string]any), counts: make(map[string]int)}
	if err := json.Unmarshal([]byte(ghTestPolicy), &fixture.policy); err != nil {
		t.Fatal(err)
	}
	fixture.candidate = GitHubCandidate{PullRequest: 7, HeadSHA: ghTestHead, BaseSHA: ghTestBase, TargetBranch: "main"}
	repo := map[string]any{"id": 42, "full_name": "owner/repo", "archived": false, "disabled": false}
	fixture.responses[""] = repo
	fixture.responses["/pulls/7"] = map[string]any{
		"id": 71, "number": 7, "state": "open", "draft": false, "merged": false,
		"head": map[string]any{"ref": "feature", "sha": ghTestHead, "repo": repo},
		"base": map[string]any{"ref": "main", "sha": ghTestBase, "repo": repo},
	}
	fixture.responses["/branches/main"] = map[string]any{"name": "main", "protected": true, "commit": map[string]any{"sha": ghTestBase}}
	fixture.responses["/compare/"+ghTestBase+"..."+ghTestHead] = map[string]any{
		"status": "ahead", "ahead_by": 1, "behind_by": 0,
		"base_commit": map[string]any{"sha": ghTestBase}, "merge_base_commit": map[string]any{"sha": ghTestBase},
	}
	for commit, tree := range map[string]string{ghTestBase: ghTestBaseTree, ghTestHead: ghTestHeadTree} {
		fixture.responses["/git/commits/"+commit] = map[string]any{"sha": commit, "tree": map[string]any{"sha": tree}}
		fixture.responses["/git/trees/"+tree] = map[string]any{"sha": tree, "truncated": false, "tree": []any{
			map[string]any{"path": ".github/workflows/ci.yml", "mode": "100644", "type": "blob", "sha": ghTestBlob},
			map[string]any{"path": ".github/workflows/release.yml", "mode": "100644", "type": "blob", "sha": "4444444444444444444444444444444444444444"},
			map[string]any{"path": ".github/scripts/guard.sh", "mode": "100755", "type": "blob", "sha": "5555555555555555555555555555555555555555"},
			map[string]any{"path": ".github/safepush.json", "mode": "100644", "type": "blob", "sha": ghTestPolicyID},
		}}
	}
	fixture.responses["/git/blobs/"+ghTestPolicyID] = map[string]any{"sha": ghTestPolicyID, "encoding": "base64", "size": len(ghTestPolicy), "content": base64.StdEncoding.EncodeToString([]byte(ghTestPolicy))}
	fixture.responses["/git/blobs/"+ghTestBlob] = map[string]any{"sha": ghTestBlob, "encoding": "base64", "size": 232, "content": base64.StdEncoding.EncodeToString([]byte(ghTestWorkflow))}
	fixture.responses["/actions/workflows"] = ghTestEnvelope("workflows", []any{
		map[string]any{"id": 101, "path": ".github/workflows/ci.yml", "state": "active"},
		map[string]any{"id": 102, "path": ".github/workflows/release.yml", "state": "active"},
		map[string]any{"id": 103, "path": "dynamic/github-code-scanning/codeql", "state": "active"},
	})
	run := map[string]any{
		"id": 201, "workflow_id": 101, "run_number": 11, "run_attempt": 1, "check_suite_id": 301,
		"path": ".github/workflows/ci.yml", "event": "pull_request", "head_sha": ghTestHead, "head_branch": "feature",
		"status": "completed", "conclusion": "success", "repository": repo, "head_repository": repo,
		"pull_requests": []any{map[string]any{
			"id": 71, "number": 7, "url": "https://api.github.com/repos/owner/repo/pulls/7",
			"head": map[string]any{"ref": "feature", "sha": ghTestHead, "repo": map[string]any{"id": 42}},
			"base": map[string]any{"ref": "main", "sha": ghTestBase, "repo": map[string]any{"id": 42}},
		}}, "referenced_workflows": []any{},
	}
	fixture.responses["/actions/runs"] = ghTestEnvelope("workflow_runs", []any{run})
	fixture.responses["/actions/runs/201"] = run
	fixture.setJobs([]string{"unit", "race"})
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	fixture.client = &http.Client{Transport: githubFixtureTransport{t: t, base: server.Client().Transport, target: target}}
	return fixture
}

func ghTestEnvelope(key string, items []any) map[string]any {
	return map[string]any{"total_count": len(items), key: items}
}

func (fixture *githubHTTPSFixture) setJobs(names []string) {
	jobs, checks := make([]any, 0, len(names)), make([]any, 0, len(names))
	for index, name := range names {
		id := 401 + index
		jobs = append(jobs, map[string]any{
			"id": id, "run_id": 201, "run_attempt": 1, "head_sha": ghTestHead, "head_branch": "feature", "name": name,
			"status": "completed", "conclusion": "success", "check_run_url": fmt.Sprintf("https://api.github.com/repos/owner/repo/check-runs/%d", id),
			"steps": []any{
				map[string]any{"name": "Set up job", "number": 1, "status": "completed", "conclusion": "success"},
				map[string]any{"name": "Run tests", "number": 3, "status": "completed", "conclusion": "success"},
				map[string]any{"name": "Complete job", "number": 7, "status": "completed", "conclusion": "success"},
			},
		})
		checks = append(checks, map[string]any{
			"id": id, "name": name, "head_sha": ghTestHead, "status": "completed", "conclusion": "success",
			"check_suite": map[string]any{"id": 301}, "app": map[string]any{"id": 15368, "slug": "github-actions"},
		})
	}
	fixture.responses["/actions/runs/201/attempts/1/jobs"] = ghTestEnvelope("jobs", jobs)
	fixture.responses["/check-suites/301/check-runs"] = ghTestEnvelope("check_runs", checks)
}

func (fixture *githubHTTPSFixture) setRequiredWorkflow(contents string) {
	// The baseline uses a separately computed known Git blob hash. Mutations
	// produce another native-shaped object so the parser, not a hash mismatch,
	// rejects a workflow whose failed outcomes could have success conclusions.
	digest := sha1.New() // #nosec G401 -- synthetic Git object identifier.
	_, _ = fmt.Fprintf(digest, "blob %d%c%s", len(contents), 0, contents)
	objectID := fmt.Sprintf("%x", digest.Sum(nil))
	for _, treeID := range []string{ghTestBaseTree, ghTestHeadTree} {
		tree := fixture.responses["/git/trees/"+treeID].(map[string]any)
		ghTestFirst(tree, "tree")["sha"] = objectID
	}
	fixture.responses["/git/blobs/"+objectID] = map[string]any{
		"sha": objectID, "encoding": "base64", "size": len(contents),
		"content": base64.StdEncoding.EncodeToString([]byte(contents)),
	}
}

func (fixture *githubHTTPSFixture) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	suffix := strings.TrimPrefix(request.URL.Path, "/repos/owner/repo")
	fixture.counts[suffix]++
	count := fixture.counts[suffix]
	fixture.requests = append(fixture.requests, request.URL.RequestURI())
	if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer test-token" {
		fixture.t.Error("unexpected method or synthetic authorization header")
	}
	if suffix == "/actions/runs" && (request.URL.Query().Get("event") != "pull_request" || request.URL.Query().Get("head_sha") != ghTestHead) {
		fixture.t.Error("run query lacks exact event and candidate filter")
	}
	writer.Header().Set("Content-Type", "application/json")
	if fixture.reply != nil && fixture.reply(writer, request, count) {
		return
	}
	original, exists := fixture.responses[suffix]
	if !exists {
		fixture.t.Errorf("unexpected API route: %s", suffix)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	data, err := json.Marshal(original)
	if err != nil {
		fixture.t.Error(err)
		return
	}
	var response map[string]any
	if err = json.Unmarshal(data, &response); err != nil {
		fixture.t.Error(err)
		return
	}
	if pageText := request.URL.Query().Get("page"); pageText != "" {
		page, pageErr := strconv.Atoi(pageText)
		if pageErr != nil || page <= 0 || request.URL.Query().Get("per_page") != "100" {
			fixture.t.Error("invalid pagination request")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, key := range []string{"workflows", "workflow_runs", "jobs", "check_runs"} {
			if all, ok := response[key].([]any); ok {
				start := min((page-1)*100, len(all))
				response[key] = all[start:min(start+100, len(all))]
			}
		}
	}
	if fixture.mutate != nil {
		fixture.mutate(request, count, response)
	}
	if err = json.NewEncoder(writer).Encode(response); err != nil {
		fixture.t.Error(err)
	}
}

func (fixture *githubHTTPSFixture) verify() error {
	return VerifyGitHub(context.Background(), fixture.client, "test-token", fixture.policy, fixture.candidate)
}

func ghTestFirst(response map[string]any, key string) map[string]any {
	return response[key].([]any)[0].(map[string]any)
}

func TestGitHubHTTPSAdmissionAndTrustedPolicy(t *testing.T) {
	fixture := newGitHubHTTPSFixture(t)
	policy, err := ReadGitHubPolicy(context.Background(), fixture.client, "test-token", "owner/repo", ghTestBase)
	if err != nil || !reflect.DeepEqual(policy, fixture.policy) {
		t.Fatalf("policy result = %#v, %v", policy, err)
	}
	if err = fixture.verify(); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	for _, required := range []string{"/git/commits/" + ghTestBase, "/git/trees/" + ghTestBaseTree, "/git/trees/" + ghTestHeadTree, "/git/blobs/" + ghTestBlob, "/actions/runs/201/attempts/1/jobs", "/check-suites/301/check-runs", "/actions/runs/201"} {
		if fixture.counts[required] == 0 {
			t.Errorf("missing native binding read: %s", required)
		}
	}
	if fixture.counts["/pulls/7"] != 2 || fixture.counts["/branches/main"] != 2 || fixture.counts["/actions/runs"] != 2 {
		t.Error("successful admission must re-read PR, protected target, and latest runs")
	}
}

func TestGitHubSuccessConclusionsCannotHideContinueOnError(t *testing.T) {
	for _, scope := range []string{"job", "step"} {
		for _, value := range []string{"true", "${{ false }}", "null", "'false'", "false"} {
			t.Run(scope+"_"+value, func(t *testing.T) {
				fixture := newGitHubHTTPSFixture(t)
				var contents string
				if scope == "job" {
					contents = strings.Replace(ghTestWorkflow, "    steps:\n", "    continue-on-error: "+value+"\n    steps:\n", 1)
				} else {
					contents = strings.Replace(ghTestWorkflow, "        run: go test ./...\n", "        run: go test ./...\n        continue-on-error: "+value+"\n", 1)
				}
				fixture.setRequiredWorkflow(contents)
				// Base and head both have this exact blob. Every REST workflow,
				// job, check and step still reports completed/success, which is
				// realistic for a failed step with continue-on-error: true.
				err := fixture.verify()
				if value == "false" {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				if !errors.Is(err, ErrGitHubSource) {
					t.Fatalf("API success admitted unsafe accepted workflow: %v", err)
				}
				if fixture.counts["/actions/runs"] != 0 {
					t.Fatal("unsafe source was not rejected before trusting run statuses")
				}
			})
		}
	}
}

func TestGitHubWorkflowBlobMustMatchTrustedObject(t *testing.T) {
	fixture := newGitHubHTTPSFixture(t)
	fixture.mutate = func(request *http.Request, _ int, response map[string]any) {
		if strings.HasSuffix(request.URL.Path, "/git/blobs/"+ghTestBlob) {
			response["content"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(ghTestWorkflow, "unit", "evil", 1)))
		}
	}
	if err := fixture.verify(); !errors.Is(err, ErrGitHubSource) {
		t.Fatalf("unverified workflow blob admitted: %v", err)
	}
}

func TestGitHubOptionalReferencedWorkflowsAndExcludedGate(t *testing.T) {
	fixture := newGitHubHTTPSFixture(t)
	fixture.mutate = func(request *http.Request, _ int, response map[string]any) {
		if strings.HasSuffix(request.URL.Path, "/actions/runs") {
			delete(ghTestFirst(response, "workflow_runs"), "referenced_workflows")
			response["workflow_runs"] = append(response["workflow_runs"].([]any), map[string]any{"id": 900, "workflow_id": 999, "path": "organization/required-verifier.yml", "status": "in_progress"})
			response["total_count"] = 2
		}
		if strings.HasSuffix(request.URL.Path, "/actions/runs/201") {
			delete(response, "referenced_workflows")
		}
	}
	if err := fixture.verify(); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubPendingIsOnlyUnfinishedRequiredRuns(t *testing.T) {
	for _, status := range []string{"absent", "queued", "in_progress", "waiting", "requested", "pending"} {
		t.Run(status, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			fixture.mutate = func(request *http.Request, _ int, response map[string]any) {
				if !strings.HasSuffix(request.URL.Path, "/actions/runs") {
					return
				}
				if status == "absent" {
					response["total_count"], response["workflow_runs"] = 0, []any{}
				} else {
					run := ghTestFirst(response, "workflow_runs")
					run["status"], run["conclusion"] = status, nil
				}
			}
			if err := fixture.verify(); !errors.Is(err, ErrGitHubPending) {
				t.Fatalf("got %v, want pending", err)
			}
			if fixture.counts["/actions/runs/201/attempts/1/jobs"] != 0 {
				t.Fatal("fetched jobs before required runs completed")
			}
		})
	}
	for _, conclusion := range []string{"failure", "cancelled", "skipped", "neutral", "timed_out", "action_required", ""} {
		t.Run("completed_"+conclusion, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			fixture.mutate = func(request *http.Request, _ int, response map[string]any) {
				if strings.HasSuffix(request.URL.Path, "/actions/runs") {
					ghTestFirst(response, "workflow_runs")["conclusion"] = conclusion
				}
			}
			if err := fixture.verify(); !errors.Is(err, ErrCheckNotSuccessful) {
				t.Fatalf("got %v, want completed failure", err)
			}
		})
	}
}

func TestGitHubRejectsSpoofingAndIncompleteExecution(t *testing.T) {
	cases := []struct {
		name   string
		suffix string
		change func(map[string]any)
	}{
		{"repository_name_reused", "", func(v map[string]any) { v["id"] = 999 }},
		{"unprotected_target", "/branches/main", func(v map[string]any) { v["protected"] = false }},
		{"wrong_pr_head", "/pulls/7", func(v map[string]any) { v["head"].(map[string]any)["sha"] = ghTestOther }},
		{"stale_pr_base", "/pulls/7", func(v map[string]any) { v["base"].(map[string]any)["sha"] = ghTestOther }},
		{"draft_pr", "/pulls/7", func(v map[string]any) { v["draft"] = true }},
		{"closed_pr", "/pulls/7", func(v map[string]any) { v["state"] = "closed" }},
		{"diverged_head", "/compare/" + ghTestBase + "..." + ghTestHead, func(v map[string]any) { v["behind_by"] = 1 }},
		{"wrong_commit_tree_binding", "/git/commits/" + ghTestHead, func(v map[string]any) { v["sha"] = ghTestOther }},
		{"wrong_tree_sha", "/git/trees/" + ghTestHeadTree, func(v map[string]any) { v["sha"] = ghTestHead }},
		{"truncated_tree", "/git/trees/" + ghTestHeadTree, func(v map[string]any) { v["truncated"] = true }},
		{"changed_required_workflow", "/git/trees/" + ghTestHeadTree, func(v map[string]any) { ghTestFirst(v, "tree")["sha"] = ghTestOther }},
		{"changed_excluded_workflow", "/git/trees/" + ghTestHeadTree, func(v map[string]any) { v["tree"].([]any)[1].(map[string]any)["sha"] = ghTestOther }},
		{"changed_workflow_helper", "/git/trees/" + ghTestHeadTree, func(v map[string]any) { v["tree"].([]any)[2].(map[string]any)["sha"] = ghTestOther }},
		{"symlink_workflow", "/git/trees/" + ghTestHeadTree, func(v map[string]any) { ghTestFirst(v, "tree")["mode"] = "120000" }},
		{"extra_candidate_workflow", "/git/trees/" + ghTestHeadTree, func(v map[string]any) {
			v["tree"] = append(v["tree"].([]any), map[string]any{"path": ".github/workflows/spoof.yml", "type": "blob", "mode": "100644", "sha": ghTestOther})
		}},
		{"missing_excluded_workflow", "/git/trees/" + ghTestHeadTree, func(v map[string]any) { v["tree"] = v["tree"].([]any)[:1] }},
		{"disabled_required_workflow", "/actions/workflows", func(v map[string]any) { ghTestFirst(v, "workflows")["state"] = "disabled_manually" }},
		{"wrong_workflow_id_same_name", "/actions/runs", func(v map[string]any) { ghTestFirst(v, "workflow_runs")["workflow_id"] = 103 }},
		{"wrong_run_event", "/actions/runs", func(v map[string]any) { ghTestFirst(v, "workflow_runs")["event"] = "push" }},
		{"wrong_run_head", "/actions/runs", func(v map[string]any) { ghTestFirst(v, "workflow_runs")["head_sha"] = ghTestOther }},
		{"wrong_run_repository", "/actions/runs", func(v map[string]any) { ghTestFirst(v, "workflow_runs")["repository"].(map[string]any)["id"] = 43 }},
		{"missing_pr_association", "/actions/runs", func(v map[string]any) { ghTestFirst(v, "workflow_runs")["pull_requests"] = []any{} }},
		{"same_sha_other_pr", "/actions/runs", func(v map[string]any) { ghTestFirst(ghTestFirst(v, "workflow_runs"), "pull_requests")["number"] = 8 }},
		{"wrong_pr_native_id", "/actions/runs", func(v map[string]any) { ghTestFirst(ghTestFirst(v, "workflow_runs"), "pull_requests")["id"] = 72 }},
		{"retargeted_pr_run", "/actions/runs", func(v map[string]any) {
			ghTestFirst(ghTestFirst(v, "workflow_runs"), "pull_requests")["base"].(map[string]any)["ref"] = "master"
		}},
		{"stale_run_base", "/actions/runs", func(v map[string]any) {
			ghTestFirst(ghTestFirst(v, "workflow_runs"), "pull_requests")["base"].(map[string]any)["sha"] = ghTestOther
		}},
		{"wrong_run_base_repository", "/actions/runs", func(v map[string]any) {
			ghTestFirst(ghTestFirst(v, "workflow_runs"), "pull_requests")["base"].(map[string]any)["repo"].(map[string]any)["id"] = 43
		}},
		{"wrong_associated_head", "/actions/runs", func(v map[string]any) {
			ghTestFirst(ghTestFirst(v, "workflow_runs"), "pull_requests")["head"].(map[string]any)["sha"] = ghTestOther
		}},
		{"reusable_chain_without_policy", "/actions/runs", func(v map[string]any) {
			ghTestFirst(v, "workflow_runs")["referenced_workflows"] = []any{map[string]any{"path": "owner/other/workflow.yml"}}
		}},
		{"unknown_run_status", "/actions/runs", func(v map[string]any) { ghTestFirst(v, "workflow_runs")["status"] = "unrecognized" }},
		{"duplicate_run", "/actions/runs", func(v map[string]any) {
			v["workflow_runs"] = append(v["workflow_runs"].([]any), ghTestFirst(v, "workflow_runs"))
			v["total_count"] = 2
		}},
		{"wrong_job_attempt", "/actions/runs/201/attempts/1/jobs", func(v map[string]any) { ghTestFirst(v, "jobs")["run_attempt"] = 2 }},
		{"wrong_job_run", "/actions/runs/201/attempts/1/jobs", func(v map[string]any) { ghTestFirst(v, "jobs")["run_id"] = 202 }},
		{"wrong_job_head", "/actions/runs/201/attempts/1/jobs", func(v map[string]any) { ghTestFirst(v, "jobs")["head_sha"] = ghTestOther }},
		{"wrong_check_url_host", "/actions/runs/201/attempts/1/jobs", func(v map[string]any) {
			ghTestFirst(v, "jobs")["check_run_url"] = "https://example.invalid/check-runs/401"
		}},
		{"duplicate_job", "/actions/runs/201/attempts/1/jobs", func(v map[string]any) { v["jobs"].([]any)[1] = ghTestFirst(v, "jobs") }},
		{"empty_steps", "/actions/runs/201/attempts/1/jobs", func(v map[string]any) { ghTestFirst(v, "jobs")["steps"] = []any{} }},
		{"skipped_success_step", "/actions/runs/201/attempts/1/jobs", func(v map[string]any) { ghTestFirst(ghTestFirst(v, "jobs"), "steps")["conclusion"] = "skipped" }},
		{"failed_step_conclusion", "/actions/runs/201/attempts/1/jobs", func(v map[string]any) { ghTestFirst(ghTestFirst(v, "jobs"), "steps")["conclusion"] = "failure" }},
		{"wrong_check_app", "/check-suites/301/check-runs", func(v map[string]any) { ghTestFirst(v, "check_runs")["app"].(map[string]any)["id"] = 123 }},
		{"wrong_check_suite", "/check-suites/301/check-runs", func(v map[string]any) { ghTestFirst(v, "check_runs")["check_suite"].(map[string]any)["id"] = 999 }},
		{"neutral_check", "/check-suites/301/check-runs", func(v map[string]any) { ghTestFirst(v, "check_runs")["conclusion"] = "neutral" }},
		{"check_job_name_mismatch", "/check-suites/301/check-runs", func(v map[string]any) { ghTestFirst(v, "check_runs")["name"] = "spoof" }},
		{"wrong_check_head", "/check-suites/301/check-runs", func(v map[string]any) { ghTestFirst(v, "check_runs")["head_sha"] = ghTestOther }},
		{"duplicate_check", "/check-suites/301/check-runs", func(v map[string]any) { v["check_runs"].([]any)[1] = ghTestFirst(v, "check_runs") }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			fixture.mutate = func(request *http.Request, _ int, response map[string]any) {
				if request.URL.Path == "/repos/owner/repo"+test.suffix {
					test.change(response)
				}
			}
			if err := fixture.verify(); err == nil || errors.Is(err, ErrGitHubPending) {
				t.Fatalf("unsafe API fixture accepted or retried: %v", err)
			}
		})
	}
}

func TestGitHubCompletedRunCannotOmitRequiredJobs(t *testing.T) {
	fixture := newGitHubHTTPSFixture(t)
	fixture.setJobs([]string{"unit"})
	if err := fixture.verify(); !errors.Is(err, ErrMissingCheck) {
		t.Fatalf("got %v, want missing job failure", err)
	}
}

func TestGitHubLatestFailureCannotReuseOlderSuccess(t *testing.T) {
	fixture := newGitHubHTTPSFixture(t)
	fixture.mutate = func(request *http.Request, _ int, response map[string]any) {
		if strings.HasSuffix(request.URL.Path, "/actions/runs") {
			older := ghTestFirst(response, "workflow_runs")
			newer := make(map[string]any)
			for key, value := range older {
				newer[key] = value
			}
			newer["id"], newer["run_number"], newer["conclusion"] = 202, 12, "failure"
			response["workflow_runs"], response["total_count"] = []any{older, newer}, 2
		}
	}
	if err := fixture.verify(); !errors.Is(err, ErrCheckNotSuccessful) {
		t.Fatalf("got %v, want newer failure", err)
	}
}

func TestGitHubStateMutationDuringCollection(t *testing.T) {
	for _, target := range []string{"pr", "branch", "run_attempt", "latest_run", "workflow"} {
		t.Run(target, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			fixture.mutate = func(request *http.Request, count int, response map[string]any) {
				suffix := strings.TrimPrefix(request.URL.Path, "/repos/owner/repo")
				switch {
				case target == "pr" && suffix == "/pulls/7" && count == 2:
					response["head"].(map[string]any)["sha"] = ghTestOther
				case target == "branch" && suffix == "/branches/main" && count == 2:
					response["commit"].(map[string]any)["sha"] = ghTestOther
				case target == "run_attempt" && suffix == "/actions/runs/201":
					response["run_attempt"] = 2
				case target == "latest_run" && suffix == "/actions/runs" && count == 2:
					run := ghTestFirst(response, "workflow_runs")
					run["run_attempt"], run["status"], run["conclusion"] = 2, "in_progress", nil
				case target == "workflow" && suffix == "/actions/workflows" && count == 2:
					ghTestFirst(response, "workflows")["id"] = 999
				}
			}
			if err := fixture.verify(); !errors.Is(err, ErrGitHubState) {
				t.Fatalf("changed collection returned %v", err)
			}
		})
	}
}

func TestGitHubBoundedCompletePagination(t *testing.T) {
	for _, mode := range []string{"valid", "missing_page", "changed_total", "duplicate_across_pages", "over_limit"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			names := make([]string, 101)
			for index := range names {
				names[index] = fmt.Sprintf("matrix-%d", index)
			}
			fixture.policy.Workflows[0].Jobs = names
			fixture.setJobs(names)
			fixture.mutate = func(request *http.Request, _ int, response map[string]any) {
				if !strings.HasSuffix(request.URL.Path, "/jobs") {
					return
				}
				if mode == "over_limit" {
					response["total_count"] = 1001
				}
				if request.URL.Query().Get("page") != "2" {
					return
				}
				switch mode {
				case "missing_page":
					response["jobs"] = []any{}
				case "changed_total":
					response["total_count"] = 102
				case "duplicate_across_pages":
					ghTestFirst(response, "jobs")["id"] = 401
				}
			}
			err := fixture.verify()
			if mode == "valid" && err != nil {
				t.Fatal(err)
			}
			if mode != "valid" && (err == nil || errors.Is(err, ErrGitHubPending)) {
				t.Fatalf("incomplete or ambiguous pagination admitted: %v", err)
			}
		})
	}
}

func TestGitHubHTTPFailuresAreBoundedAndRedacted(t *testing.T) {
	for _, mode := range []string{"redirect", "forbidden", "duplicate_json", "trailing_json", "content_type", "short_body", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			redirects := 0
			fixture.client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { redirects++; return nil }
			fixture.reply = func(writer http.ResponseWriter, request *http.Request, _ int) bool {
				if request.URL.Path != "/repos/owner/repo" {
					return false
				}
				switch mode {
				case "redirect":
					writer.Header().Set("Location", "https://example.invalid/test-token")
					writer.WriteHeader(http.StatusFound)
				case "forbidden":
					writer.WriteHeader(http.StatusForbidden)
					_, _ = fmt.Fprint(writer, `{"message":"test-token opaque-failure-sentinel"}`)
				case "duplicate_json":
					_, _ = fmt.Fprint(writer, `{"id":42,"id":999,"full_name":"owner/repo"}`)
				case "trailing_json":
					_, _ = fmt.Fprint(writer, `{"id":42,"full_name":"owner/repo"}{"extra":true}`)
				case "content_type":
					writer.Header().Set("Content-Type", "text/html")
					_, _ = fmt.Fprint(writer, `{"id":42,"full_name":"owner/repo"}`)
				case "short_body":
					writer.Header().Set("Content-Length", "1000")
					_, _ = fmt.Fprint(writer, `{"id":42}`)
				case "oversized":
					writer.Header().Set("Content-Length", strconv.Itoa(strictjson.MaxDocumentBytes+1))
					_, _ = fmt.Fprint(writer, strings.Repeat(" ", strictjson.MaxDocumentBytes+1))
				}
				return true
			}
			err := fixture.verify()
			if !errors.Is(err, ErrGitHubAPI) || strings.Contains(err.Error(), "test-token") || strings.Contains(err.Error(), "opaque-failure-sentinel") || strings.Contains(err.Error(), "example.invalid") {
				t.Fatalf("unredacted or unexpected HTTP error: %v", err)
			}
			if redirects != 0 {
				t.Fatal("adapter followed a redirect with its credential")
			}
		})
	}
}

func TestReadGitHubPolicyRejectsSymlinksAndForgedBlobs(t *testing.T) {
	for _, mode := range []string{"symlink", "executable", "blob_hash", "encoding", "size", "repository_id"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			fixture.mutate = func(request *http.Request, _ int, response map[string]any) {
				if strings.HasSuffix(request.URL.Path, "/git/trees/"+ghTestBaseTree) && (mode == "symlink" || mode == "executable") {
					entry := response["tree"].([]any)[3].(map[string]any)
					if mode == "symlink" {
						entry["mode"] = "120000"
					} else {
						entry["mode"] = "100755"
					}
				}
				if mode == "repository_id" && request.URL.Path == "/repos/owner/repo" {
					response["id"] = 99
				}
				if strings.HasSuffix(request.URL.Path, "/git/blobs/"+ghTestPolicyID) {
					switch mode {
					case "blob_hash":
						response["content"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(ghTestPolicy, "unit", "evil", 1)))
					case "encoding":
						response["encoding"] = "utf-8"
					case "size":
						response["size"] = 1
					}
				}
			}
			if _, err := ReadGitHubPolicy(context.Background(), fixture.client, "test-token", "owner/repo", ghTestBase); err == nil || errors.Is(err, ErrGitHubPending) {
				t.Fatalf("unsafe policy accepted: %v", err)
			}
		})
	}
}

func TestReadGitHubPolicyRejectsUnknownFieldsAfterBlobVerification(t *testing.T) {
	fixture := newGitHubHTTPSFixture(t)
	const policyID = "fc446526e44b5189d82ea86595794637c3b8128f"
	contents := ghTestPolicy[:len(ghTestPolicy)-1] + `,"untrusted":true}`
	tree := fixture.responses["/git/trees/"+ghTestBaseTree].(map[string]any)
	tree["tree"].([]any)[3].(map[string]any)["sha"] = policyID
	fixture.responses["/git/blobs/"+policyID] = map[string]any{
		"sha": policyID, "encoding": "base64", "size": 236,
		"content": base64.StdEncoding.EncodeToString([]byte(contents)),
	}
	if _, err := ReadGitHubPolicy(context.Background(), fixture.client, "test-token", "owner/repo", ghTestBase); !errors.Is(err, ErrPolicy) {
		t.Fatalf("correctly hashed policy with unknown field returned %v", err)
	}
}

func TestGitHubRejectsInvalidInputBeforeHTTP(t *testing.T) {
	fixture := newGitHubHTTPSFixture(t)
	fixture.candidate.HeadSHA = "invalid"
	if err := fixture.verify(); !errors.Is(err, ErrGitHubCandidate) {
		t.Fatalf("got %v", err)
	}
	if len(fixture.requests) != 0 {
		t.Fatal("sent request for invalid candidate")
	}
	if _, err := ReadGitHubPolicy(context.Background(), fixture.client, "test-token", "owner/../repo", ghTestBase); !errors.Is(err, ErrPolicy) {
		t.Fatalf("got %v", err)
	}
	if len(fixture.requests) != 0 {
		t.Fatal("sent request for invalid repository")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadGitHubPolicy(ctx, fixture.client, "test-token", "owner/repo", ghTestBase); !errors.Is(err, ErrGitHubAPI) {
		t.Fatalf("got %v", err)
	}
}

type githubCancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body githubCancelOnCloseBody) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

type githubCancelAfterReadTransport struct {
	base   http.RoundTripper
	suffix string
	nth    int
	count  int
	cancel context.CancelFunc
}

func (transport *githubCancelAfterReadTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if strings.HasSuffix(request.URL.Path, transport.suffix) {
		transport.count++
		if err == nil && transport.count == transport.nth {
			response.Body = githubCancelOnCloseBody{ReadCloser: response.Body, cancel: transport.cancel}
		}
	}
	return response, err
}

func TestGitHubCannotSucceedAfterFinalResponseCancellation(t *testing.T) {
	for _, operation := range []string{"policy", "verify"} {
		t.Run(operation, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			transport := &githubCancelAfterReadTransport{base: fixture.client.Transport, cancel: cancel}
			fixture.client.Transport = transport
			var err error
			if operation == "policy" {
				transport.suffix, transport.nth = "/git/blobs/"+ghTestPolicyID, 1
				_, err = ReadGitHubPolicy(ctx, fixture.client, "test-token", "owner/repo", ghTestBase)
			} else {
				transport.suffix, transport.nth = "/branches/main", 2
				err = VerifyGitHub(ctx, fixture.client, "test-token", fixture.policy, fixture.candidate)
			}
			if !errors.Is(err, ErrGitHubAPI) || ctx.Err() == nil {
				t.Fatalf("operation succeeded after cancellation: %v", err)
			}
		})
	}
}
