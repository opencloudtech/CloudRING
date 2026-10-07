// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package sourcecheck

import (
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxReadinessLineOffsets = 200_000

var readinessClaimPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bproduction[[:space:]-]+ready\b`),
	regexp.MustCompile(`(?i)\bready[[:space:]-]+for[[:space:]-]+production\b`),
	regexp.MustCompile(`(?i)\bproduction[[:space:]-]+readiness\b`),
	regexp.MustCompile(`(?i)\brelease[[:space:]-]+ready\b`),
	regexp.MustCompile(`(?i)\bready[[:space:]-]+for[[:space:]-]+release\b`),
	regexp.MustCompile(`(?i)\blive[[:space:]-]+ready\b`),
	regexp.MustCompile(`(?i)\bgeneral[[:space:]-]+availability\b`),
	regexp.MustCompile(`(?i)\bga\b`),
}

var (
	directNegationPrefix = regexp.MustCompile(`(?i)(?:^|.*\s)(?:not|no)(?:\s+(?:a|full|live))?$`)
	denialVerbPrefix     = regexp.MustCompile(`(?i)(?:^|.*\s)(?:does|do|did|must|should|may|can|cannot|will)\s+not\s+(?:claim|declare|assert|authorize|promote|constitute|establish)(?:\s+(?:a|full|live))?$`)
	blockingVerbPrefix   = regexp.MustCompile(`(?i)(?:^|.*\s)(?:blocks|prevents)(?:\s+(?:full|live))?$`)
	blockedSuffix        = regexp.MustCompile(`(?i)^(?:(?:claim|promotion)\s+)?(?:is|remains|stays)\s+(?:explicitly\s+)?blocked\b`)
	deniedSuffix         = regexp.MustCompile(`(?i)^(?:is\s+)?not\s+(?:claimed|authorized|established|achieved)\b`)
)

type readinessClause struct {
	start int
	end   int
}

func readinessFindings(path string, content string) []Finding {
	budget := newFindingBudget(nil)
	findings, _ := readinessFindingsWithBudget(path, content, budget)
	return findings
}

func readinessFindingsWithBudget(path string, content string, budget *findingBudget) ([]Finding, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".markdown", ".rst", ".txt":
	default:
		return nil, nil
	}
	lineOffsets, err := readinessLineOffsets(content)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	err = visitReadinessClauses(content, budget, func(clause readinessClause) error {
		value := content[clause.start:clause.end]
		searchValue := maskMarkdownBlockquotePrefixes(value)
		for _, pattern := range readinessClaimPatterns {
			for offset := 0; offset < len(searchValue); {
				match := pattern.FindStringIndex(searchValue[offset:])
				if match == nil {
					break
				}
				start := offset + match[0]
				end := offset + match[1]
				offset = end
				if readinessOccurrenceNegated(searchValue, start, end) {
					continue
				}
				line, column := lineAndColumnFromOffsets(lineOffsets, clause.start+start)
				if findingErr := budget.add(&findings, Finding{
					Rule: "readiness_overclaim", Class: "false_readiness", Line: line, Column: column,
					Message: "unqualified production or general-availability claim",
				}); findingErr != nil {
					return findingErr
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func visitReadinessClauses(content string, budget *findingBudget, visit func(readinessClause) error) error {
	start := 0
	flush := func(end int) error {
		if strings.TrimSpace(content[start:end]) != "" {
			if err := budget.consumeClause(); err != nil {
				return err
			}
			return visit(readinessClause{start: start, end: end})
		}
		return nil
	}
	for index := 0; index < len(content); {
		character := content[index]
		if character == '\n' || character == '\r' {
			if markdownLineBoundary(content, index) {
				if err := flush(index); err != nil {
					return err
				}
				index++
				if character == '\r' && index < len(content) && content[index] == '\n' {
					index++
				}
				start = index
				continue
			}
			index++
			continue
		}
		if strings.ContainsRune(".!?;,", rune(character)) {
			if err := flush(index); err != nil {
				return err
			}
			index++
			start = index
			continue
		}
		if asciiLetter(character) && (index == 0 || !asciiWord(content[index-1])) {
			end := index + 1
			for end < len(content) && asciiWord(content[end]) {
				end++
			}
			word := strings.ToLower(content[index:end])
			if conjunctionBoundary(word) && (end == len(content) || !asciiWord(content[end])) {
				if err := flush(index); err != nil {
					return err
				}
				start = end
				index = end
				continue
			}
			index = end
			continue
		}
		index++
	}
	return flush(len(content))
}

func markdownLineBoundary(content string, newline int) bool {
	lineStart := strings.LastIndex(content[:newline], "\n") + 1
	current := strings.TrimSpace(content[lineStart:newline])
	nextStart := newline + 1
	if nextStart < len(content) && content[newline] == '\r' && content[nextStart] == '\n' {
		nextStart++
	}
	nextEnd := strings.IndexByte(content[nextStart:], '\n')
	if nextEnd < 0 {
		nextEnd = len(content)
	} else {
		nextEnd += nextStart
	}
	next := strings.TrimSpace(content[nextStart:nextEnd])
	if current == "" || next == "" || strings.HasSuffix(content[lineStart:newline], "  ") {
		return true
	}
	currentQuoted, _ := markdownBlockquoteBody(current)
	nextQuoted, nextBody := markdownBlockquoteBody(next)
	if currentQuoted != nextQuoted {
		return true
	}
	if nextQuoted {
		return markdownBlockStart(nextBody)
	}
	return markdownBlockStart(next)
}

func markdownBlockquoteBody(line string) (bool, string) {
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, ">") {
		return false, line
	}
	for strings.HasPrefix(trimmed, ">") {
		trimmed = strings.TrimLeft(strings.TrimPrefix(trimmed, ">"), " \t")
	}
	return true, trimmed
}

func maskMarkdownBlockquotePrefixes(value string) string {
	masked := []byte(value)
	atLineStart := true
	for index := 0; index < len(masked); index++ {
		if atLineStart {
			for index < len(masked) && (masked[index] == ' ' || masked[index] == '\t') {
				index++
			}
			for index < len(masked) && masked[index] == '>' {
				masked[index] = ' '
				index++
				for index < len(masked) && (masked[index] == ' ' || masked[index] == '\t') {
					index++
				}
			}
			if index >= len(masked) {
				break
			}
			atLineStart = false
		}
		if masked[index] == '\n' || masked[index] == '\r' {
			atLineStart = true
		}
	}
	return string(masked)
}

func markdownBlockStart(line string) bool {
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">") || strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") || strings.HasPrefix(line, "|") {
		return true
	}
	if len(line) >= 2 && strings.ContainsRune("-*+", rune(line[0])) && (line[1] == ' ' || line[1] == '\t') {
		return true
	}
	index := 0
	for index < len(line) && line[index] >= '0' && line[index] <= '9' {
		index++
	}
	return index > 0 && index+1 < len(line) && (line[index] == '.' || line[index] == ')') && (line[index+1] == ' ' || line[index+1] == '\t')
}

func conjunctionBoundary(word string) bool {
	switch word {
	case "and", "or", "but", "however", "yet", "although":
		return true
	default:
		return false
	}
}

func asciiLetter(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
}

func asciiWord(value byte) bool {
	return asciiLetter(value) || (value >= '0' && value <= '9') || value == '_'
}

func readinessOccurrenceNegated(clause string, start int, end int) bool {
	prefixStart := start - 256
	if prefixStart < 0 {
		prefixStart = 0
	}
	suffixEnd := end + 256
	if suffixEnd > len(clause) {
		suffixEnd = len(clause)
	}
	prefix := normalizeReadinessContext(clause[prefixStart:start])
	suffix := normalizeReadinessContext(clause[end:suffixEnd])
	return directNegationPrefix.MatchString(prefix) || denialVerbPrefix.MatchString(prefix) || blockingVerbPrefix.MatchString(prefix) ||
		blockedSuffix.MatchString(suffix) || deniedSuffix.MatchString(suffix)
}

func normalizeReadinessContext(value string) string {
	value = strings.ReplaceAll(value, "-", " ")
	return strings.Join(strings.Fields(value), " ")
}

func readinessLineOffsets(content string) ([]int, error) {
	offsets := []int{0}
	for index := 0; index < len(content); index++ {
		if content[index] == '\n' {
			if len(offsets) >= maxReadinessLineOffsets {
				return nil, errors.New("readiness structure exceeds the source-safety line budget")
			}
			offsets = append(offsets, index+1)
		}
	}
	return offsets, nil
}

func lineAndColumnFromOffsets(offsets []int, offset int) (int, int) {
	lineIndex := sort.Search(len(offsets), func(index int) bool { return offsets[index] > offset }) - 1
	if lineIndex < 0 {
		lineIndex = 0
	}
	return lineIndex + 1, offset - offsets[lineIndex] + 1
}
