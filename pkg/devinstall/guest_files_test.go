//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func guestTestRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func TestGuestWritesPreserveOutsideFilesAndIdenticalConfigurations(t *testing.T) {
	root := guestTestRoot(t)
	payload := []byte("owned configuration")
	if err := guestWrite(root, "config", payload, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := root.Stat("config")
	if err != nil {
		t.Fatal(err)
	}
	if err := guestWrite(root, "config", payload, 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := root.Stat("config")
	if err != nil || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		t.Fatal("identical replay rewrote accepted configuration")
	}
	if err := guestWrite(root, "config", []byte("updated configuration"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideRoot := guestTestRoot(t)
	outside := filepath.Join(outsideRoot.Name(), "outside")
	if err := outsideRoot.WriteFile("outside", payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink(outside, "symlink"); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(root.Name(), "hardlink")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"symlink", "hardlink", "../outside"} {
		if err := guestWrite(root, name, []byte("replacement"), 0o600); err == nil {
			t.Fatal("unsafe file accepted", name)
		}
	}
	readback, err := outsideRoot.ReadFile("outside")
	if err != nil || !bytes.Equal(readback, payload) {
		t.Fatal("outside file was changed")
	}
}

func TestGuestArchiveRejectsTraversalLinksAndDuplicateExecutables(t *testing.T) {
	for _, kind := range []string{"valid", "traversal", "symlink", "duplicate", "missing"} {
		t.Run(kind, func(t *testing.T) {
			root := guestTestRoot(t)
			if err := guestMkdir(root, "bin"); err != nil {
				t.Fatal(err)
			}
			var archive bytes.Buffer
			compressed := gzip.NewWriter(&archive)
			writer := tar.NewWriter(compressed)
			name := "bin/tool"
			entryType := byte(tar.TypeReg)
			if kind == "traversal" {
				name = "../outside"
			}
			if kind == "symlink" {
				entryType = tar.TypeSymlink
			}
			if kind == "missing" {
				name = "bin/other"
			}
			count := 1
			if kind == "duplicate" {
				count = 2
			}
			for range count {
				header := &tar.Header{Name: name, Mode: 0o700, Typeflag: entryType}
				if entryType == tar.TypeReg {
					header.Size = 4
				} else {
					header.Linkname = "../outside"
				}
				if err := writer.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if entryType == tar.TypeReg {
					if _, err := writer.Write([]byte("test")); err != nil {
						t.Fatal(err)
					}
				}
			}
			if writer.Close() != nil || compressed.Close() != nil {
				t.Fatal("encode archive")
			}
			if err := root.WriteFile("archive", archive.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			err := guestExtract(root, "archive", "bin", map[string]string{"bin/tool": "tool"}, false)
			if (err == nil) != (kind == "valid") {
				t.Fatal("archive acceptance mismatch", kind, err)
			}
		})
	}
}

func TestGuestArtifactCacheRequiresFullChecksumAndSafeFile(t *testing.T) {
	root := guestTestRoot(t)
	if err := guestMkdir(root, "downloads"); err != nil {
		t.Fatal(err)
	}
	payload := []byte("exact verified artifact")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	if err := root.WriteFile("downloads/"+digest, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := Download{Version: "v1.2.3", URL: "https://github.com/example/tool", SHA256: digest}
	if _, err := guestDownload(context.Background(), root, artifact, []string{"github.com"}); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("downloads/"+digest, []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := guestDownload(context.Background(), root, artifact, []string{"github.com"}); err == nil {
		t.Fatal("corrupted cache accepted")
	}
	artifact.SHA256 = strings.Repeat("a", 64)
	if _, err := guestDownload(context.Background(), root, artifact, []string{"example.invalid"}); err == nil {
		t.Fatal("undeclared artifact origin accepted")
	}
}

func TestGuestPostgreSQLDirectoryRejectsPreexistingContent(t *testing.T) {
	root := guestTestRoot(t)
	if err := root.Mkdir("postgresql-data", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("postgresql-data/keep", []byte("existing data"), 0o600); err != nil {
		t.Fatal(err)
	}
	bootstrap := &guestBootstrap{root: root}
	if err := bootstrap.preparePostgreSQLDirectory(); err == nil {
		t.Fatal("existing database directory acquired new ownership intent")
	}
	readback, err := root.ReadFile("postgresql-data/keep")
	if err != nil || string(readback) != "existing data" {
		t.Fatal("unowned database data changed")
	}
	if bootstrap.journal.DatabaseDirectory != nil || len(bootstrap.journal.Completed) != 0 {
		t.Fatal("rejected database directory was journaled")
	}
}

// CI invokes this test in its pinned Linux container after asserting UID 0.
// Every operation stays under t.TempDir; it never accesses guestDirectory.
func TestGuestPostgreSQLDirectoryReplayAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("real root-to-PostgreSQL UID transition is verified by the root CI invocation")
	}
	for _, stage := range []string{"before-intent", "after-intent", "after-mkdir", "after-identity", "after-chown"} {
		t.Run(stage, func(t *testing.T) {
			root := guestTestRoot(t)
			bootstrap := &guestBootstrap{root: root}
			if stage != "before-intent" {
				bootstrap.journal.Completed = []string{"postgresql-directory-intent"}
				if err := bootstrap.saveJournal(); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "after-mkdir" || stage == "after-identity" || stage == "after-chown" {
				if err := root.Mkdir("postgresql-data", 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "after-identity" || stage == "after-chown" {
				identity, rootOwned, err := guestInspectDatabaseDirectory(root, "postgresql-data")
				if err != nil || !rootOwned {
					t.Fatal("root directory identity unavailable", err)
				}
				bootstrap.journal.DatabaseDirectory = &identity
				if err := bootstrap.saveJournal(); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "after-chown" {
				if err := root.Chown("postgresql-data", 999, 999); err != nil {
					t.Fatal(err)
				}
			}
			// Drop in-memory state: the retry must use the durable checkpoint.
			bootstrap = &guestBootstrap{root: root}
			if stage != "before-intent" {
				payload, err := root.ReadFile("bootstrap-journal.json")
				if err != nil || json.Unmarshal(payload, &bootstrap.journal) != nil {
					t.Fatal("read persisted interruption checkpoint", err)
				}
			}
			if err := bootstrap.preparePostgreSQLDirectory(); err != nil {
				t.Fatal("interrupted directory could not resume", err)
			}
			identity, rootOwned, err := guestInspectDatabaseDirectory(root, "postgresql-data")
			if err != nil || rootOwned || bootstrap.journal.DatabaseDirectory == nil || *bootstrap.journal.DatabaseDirectory != identity {
				t.Fatal("database ownership identity was not committed", err)
			}
			if err := root.WriteFile("postgresql-data/PG_VERSION", []byte("18\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := root.Chown("postgresql-data/PG_VERSION", 999, 999); err != nil {
				t.Fatal(err)
			}
			payload, err := root.ReadFile("bootstrap-journal.json")
			if err != nil {
				t.Fatal(err)
			}
			bootstrap = &guestBootstrap{root: root}
			if json.Unmarshal(payload, &bootstrap.journal) != nil {
				t.Fatal("reload journal")
			}
			if err := bootstrap.preparePostgreSQLDirectory(); err != nil {
				t.Fatal("initialized database replay failed", err)
			}
			after, _, err := guestInspectDatabaseDirectory(root, "postgresql-data")
			data, readErr := root.ReadFile("postgresql-data/PG_VERSION")
			if err != nil || after != identity || readErr != nil || string(data) != "18\n" {
				t.Fatal("replay replaced database inode or content")
			}
			if err := root.Rename("postgresql-data", "original-database"); err != nil {
				t.Fatal(err)
			}
			if err := root.Mkdir("postgresql-data", 0o700); err != nil {
				t.Fatal(err)
			}
			if err := bootstrap.preparePostgreSQLDirectory(); err == nil {
				t.Fatal("replacement database inode adopted")
			}
			data, err = root.ReadFile("original-database/PG_VERSION")
			if err != nil || string(data) != "18\n" {
				t.Fatal("rejected replacement harmed original database")
			}
		})
	}
}

func TestGuestPostgreSQLDirectoryRejectsUnrecordedIdentityAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership boundary is verified by the root CI invocation")
	}
	for _, kind := range []string{"nonempty", "postgres-owned", "foreign-owner", "writable-mode", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := guestTestRoot(t)
			bootstrap := &guestBootstrap{root: root, journal: guestJournal{Completed: []string{"postgresql-directory-intent"}}}
			if err := root.Mkdir("original", 0o700); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				if err := root.Symlink("original", "postgresql-data"); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := root.Mkdir("postgresql-data", 0o700); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "nonempty":
					if err := root.WriteFile("postgresql-data/keep", []byte("existing"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "postgres-owned":
					if err := root.Chown("postgresql-data", 999, 999); err != nil {
						t.Fatal(err)
					}
				case "foreign-owner":
					if err := root.Chown("postgresql-data", 998, 999); err != nil {
						t.Fatal(err)
					}
				case "writable-mode":
					if err := root.Chmod("postgresql-data", 0o777); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := bootstrap.preparePostgreSQLDirectory(); err == nil {
				t.Fatal("unsafe database directory acquired an identity")
			}
			if bootstrap.journal.DatabaseDirectory != nil {
				t.Fatal("unsafe database identity was recorded")
			}
		})
	}
}
