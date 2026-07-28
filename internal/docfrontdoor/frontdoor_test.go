package docfrontdoor

import (
	"crypto/sha256"
	"encoding/hex"
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
	// Store only one-way fingerprints so the public guard does not disclose the
	// private identifiers that it rejects.
	forbidden := []struct {
		length int
		sha256 string
	}{
		{length: 20, sha256: "ba415b48d22794dc48d4450683c6bba7ceb89ec35ceb7c3a028abaa128444e7c"},
		{length: 20, sha256: "4e538bf0dc25d9d384f9a0f2cc9cf913679483e1d500fd7347919de9cef8adfa"},
		{length: 10, sha256: "298343ca6d4934f16f32cba169902d02d6f2da35568b113a984c7841cb7ada54"},
		{length: 18, sha256: "99f78b6204094534ebc5e299796ac979e4f77b67f9a6c86991710e5909eae2fe"},
		{length: 11, sha256: "09780addc0aca989e9cc50096a35c7d2519b557fe51b389e15639213fe20f86a"},
	}
	digestsByLength := make(map[int]map[[sha256.Size]byte]struct{})
	for _, identifier := range forbidden {
		raw, err := hex.DecodeString(identifier.sha256)
		if err != nil || len(raw) != sha256.Size {
			t.Fatalf("decode private-identifier fingerprint: %v", err)
		}
		var digest [sha256.Size]byte
		copy(digest[:], raw)
		if digestsByLength[identifier.length] == nil {
			digestsByLength[identifier.length] = make(map[[sha256.Size]byte]struct{})
		}
		digestsByLength[identifier.length][digest] = struct{}{}
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
		lower := []byte(strings.ToLower(string(data)))
		for length, digests := range digestsByLength {
			for offset := 0; offset+length <= len(lower); offset++ {
				digest := sha256.Sum256(lower[offset : offset+length])
				if _, forbidden := digests[digest]; forbidden {
					t.Errorf("%s contains a non-public consumer identifier", name)
					return nil
				}
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
