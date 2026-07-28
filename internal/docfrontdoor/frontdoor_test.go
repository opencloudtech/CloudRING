package docfrontdoor

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var markdownLink = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate front-door test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func openRepository(t *testing.T) *os.Root {
	t.Helper()
	repository, err := os.OpenRoot(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := repository.Close(); err != nil {
			t.Errorf("close repository root: %v", err)
		}
	})
	return repository
}

func TestRequiredFrontDoorDocuments(t *testing.T) {
	repository := openRepository(t)
	required := []string{
		"README.md",
		"ARCHITECTURE.md",
		"REPOSITORY_MAP.md",
		"CONTRIBUTING.md",
		"GOVERNANCE.md",
		"SECURITY.md",
		".github/CODEOWNERS",
		"docs/repository-lifecycle.md",
		"roadmap/README.md",
		"roadmap/CURRENT_STATE.md",
		"roadmap/roadmap.yaml",
	}
	for _, name := range required {
		data, err := repository.ReadFile(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.TrimSpace(string(data)) == "" {
			t.Errorf("%s is empty", name)
		}
	}

	readme, err := repository.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range []string{
		"REPOSITORY_MAP.md",
		"ARCHITECTURE.md",
		"roadmap/CURRENT_STATE.md",
		"roadmap/roadmap.yaml",
		"docs/repository-lifecycle.md",
		".github/CODEOWNERS",
	} {
		if !strings.Contains(string(readme), authority) {
			t.Errorf("README.md does not point to %s", authority)
		}
	}
}

func TestFrontDoorRelativeLinksResolve(t *testing.T) {
	repository := openRepository(t)
	documents := []string{
		"README.md",
		"ARCHITECTURE.md",
		"REPOSITORY_MAP.md",
		"docs/repository-lifecycle.md",
		"roadmap/CURRENT_STATE.md",
	}
	for _, name := range documents {
		data, err := repository.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range markdownLink.FindAllStringSubmatch(string(data), -1) {
			target := strings.TrimSpace(match[1])
			if target == "" || strings.HasPrefix(target, "#") ||
				strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			target = strings.Trim(target, "<>")
			if fragment := strings.IndexByte(target, '#'); fragment >= 0 {
				target = target[:fragment]
			}
			if target == "" {
				continue
			}
			resolved := path.Clean(path.Join(path.Dir(name), target))
			if _, err := repository.Stat(resolved); err != nil {
				t.Errorf("%s links to %q: %v", name, match[1], err)
			}
		}
	}
}

func TestPublicDocumentsDoNotNamePrivateConsumers(t *testing.T) {
	repository := openRepository(t)
	forbidden := []string{
		"cloudring-enterprise",
		"cloudring_enterprise",
		"cloudlinux",
		"cloudring_provider",
		"gitlab.corp",
	}
	err := fs.WalkDir(repository.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(path.Ext(name)) {
		case ".md", ".yaml", ".yml", ".json":
		default:
			return nil
		}
		data, err := repository.ReadFile(name)
		if err != nil {
			return err
		}
		lower := strings.ToLower(string(data))
		for _, identifier := range forbidden {
			if strings.Contains(lower, identifier) {
				t.Errorf("%s contains non-public consumer identifier %q", name, identifier)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSingleCanonicalRoadmapIndex(t *testing.T) {
	repository := openRepository(t)
	var indexes []string
	err := fs.WalkDir(repository.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if !entry.IsDir() && entry.Name() == "roadmap.yaml" {
			indexes = append(indexes, name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(indexes) != 1 || indexes[0] != "roadmap/roadmap.yaml" {
		t.Fatalf("canonical roadmap indexes = %v, want [roadmap/roadmap.yaml]", indexes)
	}
}
