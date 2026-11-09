// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// The mutant table of gremlins v0.6.0 (internal/engine/mappings.go), reduced to
// the types G2 enables: the default mutators plus INVERT_LOGICAL. A token lists
// its types in gremlins' order.
var mutantTypes = map[token.Token][]string{
	token.ADD:  {"ARITHMETIC_BASE"},
	token.DEC:  {"INCREMENT_DECREMENT"},
	token.EQL:  {"CONDITIONALS_NEGATION"},
	token.GEQ:  {"CONDITIONALS_BOUNDARY", "CONDITIONALS_NEGATION"},
	token.GTR:  {"CONDITIONALS_BOUNDARY", "CONDITIONALS_NEGATION"},
	token.INC:  {"INCREMENT_DECREMENT"},
	token.LAND: {"INVERT_LOGICAL"},
	token.LEQ:  {"CONDITIONALS_BOUNDARY", "CONDITIONALS_NEGATION"},
	token.LOR:  {"INVERT_LOGICAL"},
	token.LSS:  {"CONDITIONALS_BOUNDARY", "CONDITIONALS_NEGATION"},
	token.MUL:  {"ARITHMETIC_BASE"},
	token.NEQ:  {"CONDITIONALS_NEGATION"},
	token.QUO:  {"ARITHMETIC_BASE"},
	token.REM:  {"ARITHMETIC_BASE"},
	token.SUB:  {"INVERT_NEGATIVES", "ARITHMETIC_BASE"},
}

var replacements = map[string]map[token.Token]token.Token{
	"ARITHMETIC_BASE":       {token.ADD: token.SUB, token.MUL: token.QUO, token.QUO: token.MUL, token.REM: token.MUL, token.SUB: token.ADD},
	"CONDITIONALS_BOUNDARY": {token.GEQ: token.GTR, token.GTR: token.GEQ, token.LEQ: token.LSS, token.LSS: token.LEQ},
	"CONDITIONALS_NEGATION": {token.EQL: token.NEQ, token.GEQ: token.LSS, token.GTR: token.LEQ, token.LEQ: token.GTR, token.LSS: token.GEQ, token.NEQ: token.EQL},
	"INCREMENT_DECREMENT":   {token.DEC: token.INC, token.INC: token.DEC},
	"INVERT_LOGICAL":        {token.LAND: token.LOR, token.LOR: token.LAND},
	"INVERT_NEGATIVES":      {token.SUB: token.ADD},
}

// site is one mutant: a token at a source position and its replacement.
type site struct {
	File      string // slash path relative to the module root
	Line, Col int
	Type      string
	From, To  token.Token
}

func (s site) location() string { return fmt.Sprintf("%s:%d:%d", s.File, s.Line, s.Col) }

// tokenOf returns the token field gremlins mutates in n, if any.
func tokenOf(n ast.Node) (*token.Token, token.Pos, bool) {
	switch n := n.(type) {
	case *ast.AssignStmt:
		return &n.Tok, n.TokPos, true
	case *ast.BinaryExpr:
		return &n.Op, n.OpPos, true
	case *ast.BranchStmt:
		return &n.Tok, n.TokPos, true
	case *ast.IncDecStmt:
		return &n.Tok, n.TokPos, true
	case *ast.UnaryExpr:
		return &n.Op, n.OpPos, true
	}
	return nil, token.NoPos, false
}

// changeSet holds the candidate's lines: whole new files and changed lines of
// existing files, keyed by slash path relative to the module root.
type changeSet struct {
	newFiles map[string]bool
	lines    map[string]map[int]bool
}

func (c changeSet) contains(file string, line int) bool {
	return c.newFiles[file] || c.lines[file][line]
}

// enumerate lists the mutants on changed lines of the Go files that go build
// compiles for the packages under dirs.
func enumerate(root string, dirs []string, changes changeSet) ([]site, error) {
	files, err := compiledFiles(root, dirs)
	if err != nil {
		return nil, err
	}
	var sites []site
	for _, file := range files {
		found, err := fileSites(filepath.Join(root, filepath.FromSlash(file)), file, changes)
		if err != nil {
			return nil, err
		}
		sites = append(sites, found...)
	}
	sort.SliceStable(sites, func(i, j int) bool {
		a, b := sites[i], sites[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Col < b.Col
	})
	return sites, nil
}

// compiledFiles returns the GoFiles and CgoFiles that `go list` reports for
// the packages under dirs, as slash paths relative to root. A package outside
// the module root and a listed file that is not a regular file in its package
// directory (a symbolic link, for one) are errors: the tool would not mutate
// the code go build compiles.
func compiledFiles(root string, dirs []string) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	realRoot, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	args := []string{"list", "-json=Dir,GoFiles,CgoFiles"}
	for _, dir := range dirs {
		args = append(args, "./"+dir+"/...")
	}
	cmd := exec.Command("go", args...) // #nosec G204 -- fixed go binary; the package directories are validated relative to the module root.
	cmd.Dir = abs
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	var files []string
	decoder := json.NewDecoder(bytes.NewReader(out))
	for decoder.More() {
		var pkg struct {
			Dir               string
			GoFiles, CgoFiles []string
		}
		if err := decoder.Decode(&pkg); err != nil {
			return nil, err
		}
		realDir, err := filepath.EvalSymlinks(pkg.Dir)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(realRoot, realDir)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("package directory %s is outside the module root", pkg.Dir)
		}
		for _, name := range append(pkg.GoFiles, pkg.CgoFiles...) {
			info, err := os.Lstat(filepath.Join(realDir, name))
			if err != nil {
				return nil, err
			}
			if name != filepath.Base(name) || !info.Mode().IsRegular() {
				return nil, fmt.Errorf("%s in %s is not a regular file of the package directory", name, pkg.Dir)
			}
			files = append(files, path.Join(filepath.ToSlash(rel), name))
		}
	}
	sort.Strings(files)
	return files, nil
}

// fileSites lists the mutants of one file. Positions are physical file
// positions: //line directives are ignored, so they match the diff.
func fileSites(name, rel string, changes changeSet) ([]site, error) {
	src, err := os.ReadFile(name) // #nosec G304 -- a Go file of a package the operator named.
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var sites []site
	ast.Inspect(file, func(n ast.Node) bool {
		tok, pos, ok := tokenOf(n)
		if !ok {
			return true
		}
		p := fset.PositionFor(pos, false)
		if !changes.contains(rel, p.Line) {
			return true
		}
		for _, kind := range mutantTypes[*tok] {
			sites = append(sites, site{File: rel, Line: p.Line, Col: p.Column, Type: kind, From: *tok, To: replacements[kind][*tok]})
		}
		return true
	})
	return sites, nil
}

// apply returns src with the mutant applied the way gremlins applies it: the
// token of that one AST node is replaced and the file is printed with
// go/printer, which parenthesizes the changed tree where its meaning needs it.
func apply(src []byte, s site) ([]byte, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, s.File, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	applied := false
	ast.Inspect(file, func(n ast.Node) bool {
		tok, pos, ok := tokenOf(n)
		if !ok || applied {
			return !applied
		}
		if p := fset.PositionFor(pos, false); p.Line == s.Line && p.Column == s.Col && *tok == s.From {
			*tok = s.To
			applied = true
		}
		return !applied
	})
	if !applied {
		return nil, fmt.Errorf("no %s token at %s", s.From, s.location())
	}
	var out bytes.Buffer
	if err := printer.Fprint(&out, fset, file); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
