// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package safepush

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const ghTestEmptyBlob = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"

// These cases change one provider field consistently on every read that
// carries it, so the named check alone must reject the snapshot, with the
// error class that check returns.

func (fixture *githubHTTPSFixture) ghRun() map[string]any {
	return fixture.responses["/actions/runs/201"].(map[string]any)
}

func (fixture *githubHTTPSFixture) ghList(route, key string) []any {
	return fixture.responses[route].(map[string]any)[key].([]any)
}

func (fixture *githubHTTPSFixture) ghJob(index int) map[string]any {
	return fixture.ghList("/actions/runs/201/attempts/1/jobs", "jobs")[index].(map[string]any)
}

func (fixture *githubHTTPSFixture) ghEditTrees(edit func(treeID string, entries []any) []any) {
	for _, treeID := range []string{ghTestBaseTree, ghTestHeadTree} {
		tree := fixture.responses["/git/trees/"+treeID].(map[string]any)
		tree["tree"] = edit(treeID, tree["tree"].([]any))
	}
}

func (fixture *githubHTTPSFixture) ghOnlyJob(name string) {
	fixture.policy.Workflows[0].Jobs = []string{name}
	fixture.setJobs([]string{name})
}

func ghTreeEntry(path, entryType, mode, sha string) map[string]any {
	return map[string]any{"path": path, "type": entryType, "mode": mode, "sha": sha}
}

func TestGitHubSingleFieldSpoofing(t *testing.T) {
	cases := []struct {
		name string
		want error
		edit func(*githubHTTPSFixture)
	}{
		{"pr id zero", ErrGitHubState, func(f *githubHTTPSFixture) { f.responses["/pulls/7"].(map[string]any)["id"] = 0 }},
		{"pr head repository id zero", ErrGitHubState, func(f *githubHTTPSFixture) {
			f.responses["/pulls/7"].(map[string]any)["head"].(map[string]any)["repo"] = map[string]any{"id": 0, "full_name": "owner/repo"}
		}},
		{"comparison diverged", ErrGitHubState, func(f *githubHTTPSFixture) {
			f.responses["/compare/"+ghTestBase+"..."+ghTestHead].(map[string]any)["status"] = "diverged"
		}},
		{"comparison without ahead_by", ErrGitHubState, func(f *githubHTTPSFixture) {
			delete(f.responses["/compare/"+ghTestBase+"..."+ghTestHead].(map[string]any), "ahead_by")
		}},
		{"comparison ahead_by zero", ErrGitHubState, func(f *githubHTTPSFixture) {
			f.responses["/compare/"+ghTestBase+"..."+ghTestHead].(map[string]any)["ahead_by"] = 0
		}},
		{"tree entry with invalid object id", ErrGitHubSource, func(f *githubHTTPSFixture) {
			f.ghEditTrees(func(_ string, e []any) []any { return append(e, ghTreeEntry("README.md", "blob", "100644", "zz")) })
		}},
		{"tree entry with padded path", ErrGitHubSource, func(f *githubHTTPSFixture) {
			f.ghEditTrees(func(_ string, e []any) []any {
				return append(e, ghTreeEntry(" README.md", "blob", "100644", ghTestOther))
			})
		}},
		{"guarded directory with file mode", ErrGitHubSource, func(f *githubHTTPSFixture) {
			f.ghEditTrees(func(_ string, e []any) []any {
				return append(e, ghTreeEntry(".github/scripts/lib", "tree", "100644", ghTestOther))
			})
		}},
		{"guarded entry of another object type", ErrGitHubSource, func(f *githubHTTPSFixture) {
			f.ghEditTrees(func(_ string, e []any) []any {
				return append(e, ghTreeEntry(".github/scripts/lib", "commit", "040000", ghTestOther))
			})
		}},
		{"excluded workflow replaced by an unlisted one", ErrGitHubSource, func(f *githubHTTPSFixture) {
			f.ghEditTrees(func(_ string, e []any) []any {
				e[1].(map[string]any)["path"] = ".github/workflows/spoof.yml"
				return e
			})
		}},
		{"workflow id zero", ErrGitHubSource, func(f *githubHTTPSFixture) {
			f.ghList("/actions/workflows", "workflows")[2].(map[string]any)["id"] = 0
		}},
		{"null total_count", ErrGitHubAPI, func(f *githubHTTPSFixture) {
			f.responses["/actions/workflows"] = map[string]any{"total_count": nil, "workflows": []any{}}
		}},
		{"string total_count", ErrGitHubAPI, func(f *githubHTTPSFixture) {
			f.responses["/actions/workflows"] = map[string]any{"total_count": "0", "workflows": []any{}}
		}},
		{"null item list", ErrGitHubAPI, func(f *githubHTTPSFixture) {
			f.responses["/actions/workflows"] = map[string]any{"total_count": 0, "workflows": nil}
		}},
		{"run id zero", ErrGitHubRun, func(f *githubHTTPSFixture) { f.ghRun()["id"] = 0 }},
		{"run number zero", ErrGitHubRun, func(f *githubHTTPSFixture) { f.ghRun()["run_number"] = 0 }},
		{"run attempt zero", ErrGitHubRun, func(f *githubHTTPSFixture) { f.ghRun()["run_attempt"] = 0 }},
		{"run check suite zero", ErrGitHubRun, func(f *githubHTTPSFixture) { f.ghRun()["check_suite_id"] = 0 }},
		{"duplicate run id with a newer number", ErrGitHubRun, func(f *githubHTTPSFixture) {
			newer := maps.Clone(f.ghRun())
			newer["run_number"] = 12
			f.responses["/actions/runs"] = ghTestEnvelope("workflow_runs", []any{f.ghRun(), newer})
		}},
		{"run of another workflow id", ErrGitHubRun, func(f *githubHTTPSFixture) { f.ghRun()["workflow_id"] = 103 }},
		{"push run", ErrGitHubRun, func(f *githubHTTPSFixture) { f.ghRun()["event"] = "push" }},
		{"run of another branch", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghRun()["head_branch"] = "other"
			f.ghJob(0)["head_branch"], f.ghJob(1)["head_branch"] = "other", "other"
		}},
		{"run of another head", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghRun()["head_sha"] = ghTestOther
			for _, route := range []string{"/actions/runs/201/attempts/1/jobs", "/check-suites/301/check-runs"} {
				key := map[bool]string{true: "jobs", false: "check_runs"}[strings.HasSuffix(route, "/jobs")]
				for _, item := range f.ghList(route, key) {
					item.(map[string]any)["head_sha"] = ghTestOther
				}
			}
		}},
		{"run in another repository id", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghRun()["repository"] = map[string]any{"id": 43, "full_name": "owner/repo"}
		}},
		{"run in another repository name", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghRun()["repository"] = map[string]any{"id": 42, "full_name": "owner/fork"}
		}},
		{"run from another head repository id", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghRun()["head_repository"] = map[string]any{"id": 43, "full_name": "owner/repo"}
		}},
		{"run from another head repository name", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghRun()["head_repository"] = map[string]any{"id": 42, "full_name": "owner/fork"}
		}},
		{"run with referenced workflows", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghRun()["referenced_workflows"] = []any{map[string]any{"path": "owner/other/workflow.yml"}}
		}},
		{"run linked to another pr id", ErrGitHubRun, func(f *githubHTTPSFixture) {
			ghTestFirst(f.ghRun(), "pull_requests")["id"] = 72
		}},
		{"job id zero", ErrGitHubRun, func(f *githubHTTPSFixture) { f.ghJob(0)["id"] = 0 }},
		{"check url without origin", ErrGitHubRun, func(f *githubHTTPSFixture) { f.ghJob(0)["check_run_url"] = "401" }},
		{"check url with leading zero", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghJob(0)["check_run_url"] = "https://api.github.com/repos/owner/repo/check-runs/0401"
		}},
		{"step number zero", ErrGitHubRun, func(f *githubHTTPSFixture) { ghTestFirst(f.ghJob(0), "steps")["number"] = 0 }},
		{"duplicate step number", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghJob(0)["steps"].([]any)[1].(map[string]any)["number"] = 1
		}},
		{"blank step name", ErrGitHubRun, func(f *githubHTTPSFixture) { ghTestFirst(f.ghJob(0), "steps")["name"] = "" }},
		{"duplicate check run", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghOnlyJob("unit")
			checks := f.ghList("/check-suites/301/check-runs", "check_runs")
			f.responses["/check-suites/301/check-runs"] = ghTestEnvelope("check_runs", []any{checks[0], checks[0]})
		}},
		{"two jobs share one check run", ErrGitHubRun, func(f *githubHTTPSFixture) {
			f.ghOnlyJob("unit")
			second := maps.Clone(f.ghJob(0))
			second["id"] = 402
			f.responses["/actions/runs/201/attempts/1/jobs"] = ghTestEnvelope("jobs", []any{f.ghJob(0), second})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			tc.edit(fixture)
			if err := fixture.verify(); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestGitHubAdmitsOrdinaryRepositoryContent(t *testing.T) {
	cases := map[string]func(*githubHTTPSFixture){
		// A PR changes code outside .github; trees list directory entries; a
		// .yml outside the workflow directory or a non-YAML file inside it is
		// not a workflow.
		"code change and directory entries": func(f *githubHTTPSFixture) {
			f.ghEditTrees(func(treeID string, e []any) []any {
				code := map[string]string{ghTestBaseTree: "3333333333333333333333333333333333333333", ghTestHeadTree: ghTestOther}[treeID]
				return append(e,
					ghTreeEntry("pkg/app.go", "blob", "100644", code),
					ghTreeEntry("docs/mkdocs.yml", "blob", "100644", "6666666666666666666666666666666666666666"),
					ghTreeEntry(".github/workflows/README.md", "blob", "100644", "7777777777777777777777777777777777777777"),
					ghTreeEntry(".github", "tree", "040000", "8888888888888888888888888888888888888888"),
					ghTreeEntry(".github/workflows", "tree", "040000", "abababababababababababababababababababab"),
					ghTreeEntry(".github/scripts", "tree", "040000", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
				)
			})
		},
		"executable workflow file": func(f *githubHTTPSFixture) {
			f.ghEditTrees(func(_ string, e []any) []any {
				e[0].(map[string]any)["mode"] = "100755"
				return e
			})
		},
		"explicitly complete lists": func(f *githubHTTPSFixture) {
			envelope := f.responses["/actions/workflows"].(map[string]any)
			envelope["incomplete_results"], envelope["truncated"] = false, false
		},
		"workflow source at the size limit": func(f *githubHTTPSFixture) {
			contents := ghTestWorkflow + "#"
			contents += strings.Repeat("#", maxWorkflowSourceBytes-len(contents)-1) + "\n"
			f.setRequiredWorkflow(contents)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			edit(fixture)
			if err := fixture.verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGitHubListLimits(t *testing.T) {
	names := func(n int) []string {
		out := make([]string, n)
		for index := range out {
			out[index] = fmt.Sprintf("matrix-%d", index)
		}
		return out
	}
	// The provider limit is inclusive: 1000 jobs span exactly ten pages.
	fixture := newGitHubHTTPSFixture(t)
	fixture.policy.Workflows[0].Jobs = names(1000)
	fixture.setJobs(names(1000))
	if err := fixture.verify(); err != nil {
		t.Fatalf("1000 jobs: %v", err)
	}
	// An over-limit total is rejected on the first page, before more reads.
	fixture = newGitHubHTTPSFixture(t)
	fixture.policy.Workflows[0].Jobs = names(101)
	fixture.setJobs(names(101))
	fixture.responses["/actions/runs/201/attempts/1/jobs"].(map[string]any)["total_count"] = 1001
	if err := fixture.verify(); !errors.Is(err, ErrGitHubAPI) {
		t.Fatalf("over-limit total: %v", err)
	}
	if got := fixture.counts["/actions/runs/201/attempts/1/jobs"]; got != 1 {
		t.Fatalf("over-limit total read %d pages, want 1", got)
	}
}

func TestReadGitHubPolicyRepositoryState(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"id zero":       func(r map[string]any) { r["id"] = 0 },
		"renamed":       func(r map[string]any) { r["full_name"] = "owner/other" },
		"archived":      func(r map[string]any) { r["archived"] = true },
		"disabled":      func(r map[string]any) { r["disabled"] = true },
		"id zero alone": func(r map[string]any) { r["id"], r["full_name"] = 0, "owner/repo" },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newGitHubHTTPSFixture(t)
			edit(fixture.responses[""].(map[string]any))
			if _, err := ReadGitHubPolicy(context.Background(), fixture.client, "test-token", "owner/repo", ghTestBase); !errors.Is(err, ErrGitHubState) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestReadGitHubPolicyRejectsEmptyBlob(t *testing.T) {
	fixture := newGitHubHTTPSFixture(t)
	fixture.responses["/git/trees/"+ghTestBaseTree].(map[string]any)["tree"].([]any)[3].(map[string]any)["sha"] = ghTestEmptyBlob
	fixture.responses["/git/blobs/"+ghTestEmptyBlob] = map[string]any{"sha": ghTestEmptyBlob, "encoding": "base64", "size": 0, "content": ""}
	if _, err := ReadGitHubPolicy(context.Background(), fixture.client, "test-token", "owner/repo", ghTestBase); !errors.Is(err, ErrGitHubSource) {
		t.Fatalf("got %v", err)
	}
}

func TestGitHubResponseAtTheDocumentLimit(t *testing.T) {
	fixture := newGitHubHTTPSFixture(t)
	body := `{"id":42,"full_name":"owner/repo","archived":false,"disabled":false}`
	body += strings.Repeat(" ", strictjson.MaxDocumentBytes-len(body))
	fixture.reply = func(writer http.ResponseWriter, request *http.Request, _ int) bool {
		if request.URL.Path != "/repos/owner/repo" {
			return false
		}
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = fmt.Fprint(writer, body)
		return true
	}
	if _, err := ReadGitHubPolicy(context.Background(), fixture.client, "test-token", "owner/repo", ghTestBase); err != nil {
		t.Fatalf("response of exactly %d bytes: %v", strictjson.MaxDocumentBytes, err)
	}
}

// githubRecordingTransport records how much time each request may take and
// stops it before any network access.
type githubRecordingTransport struct {
	calls     int
	remaining time.Duration
}

func (transport *githubRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls++
	if deadline, ok := request.Context().Deadline(); ok {
		transport.remaining = time.Until(deadline)
	}
	return nil, errors.New("stopped by test transport")
}

func TestGitHubTokenIsCheckedBeforeTransport(t *testing.T) {
	for _, malformed := range []string{"test token", "test\x7ftoken", "test\x01token", "tést"} {
		transport := &githubRecordingTransport{}
		client := &http.Client{Transport: transport}
		if _, err := ReadGitHubPolicy(context.Background(), client, malformed, "owner/repo", ghTestBase); !errors.Is(err, ErrGitHubAPI) {
			t.Errorf("token %q: %v", malformed, err)
		}
		if transport.calls != 0 {
			t.Errorf("token %q reached the transport", malformed)
		}
	}
}

func TestGitHubRequestTimeoutIsCapped(t *testing.T) {
	cases := []struct {
		timeout  time.Duration
		min, max time.Duration
	}{
		{0, 25 * time.Second, 30 * time.Second},
		{time.Hour, 25 * time.Second, 30 * time.Second},
		{50 * time.Millisecond, 0, 50 * time.Millisecond},
	}
	for _, tc := range cases {
		transport := &githubRecordingTransport{}
		client := &http.Client{Transport: transport, Timeout: tc.timeout}
		if _, err := ReadGitHubPolicy(context.Background(), client, "test-token", "owner/repo", ghTestBase); !errors.Is(err, ErrGitHubAPI) {
			t.Fatalf("timeout %v: %v", tc.timeout, err)
		}
		if transport.calls != 1 || transport.remaining <= tc.min || transport.remaining > tc.max {
			t.Errorf("client timeout %v: request may take %v, want (%v, %v]", tc.timeout, transport.remaining, tc.min, tc.max)
		}
	}
}
