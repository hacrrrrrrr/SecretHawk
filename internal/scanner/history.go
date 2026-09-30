package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/hacrrrrrrr/SecretHawk/internal/gitx"
	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

func ScanHistory(repo string) ([]model.Finding, error) {
	commits, err := gitx.History(repo)
	if err != nil { return nil, err }

	var findings []model.Finding
	for _, commit := range commits {
		data, err := gitx.ShowCommit(repo, commit)
		if err != nil { return nil, fmt.Errorf("show commit %s: %w", commit, err) }

		sc := bufio.NewScanner(bytes.NewReader(data))
		line := 0
		for sc.Scan() {
			line++
			text := sc.Text()

			// Only inspect added lines. This avoids reporting unchanged
			// context and secrets that were removed by a later commit.
			if !strings.HasPrefix(text, "+") || strings.HasPrefix(text, "+++") {
				continue
			}
			findings = append(findings, detectHistoryLine(commit, line, strings.TrimPrefix(text, "+"))...)
		}
		if err := sc.Err(); err != nil {
			return findings, fmt.Errorf("history scan: %w", err)
		}
	}
	return Deduplicate(findings), nil
}

func detectHistoryLine(commit string, line int, text string) []model.Finding {
	var out []model.Finding
	for _, r := range historyRules {
		if m := r.re.FindString(text); m != "" {
			out = append(out, model.Finding{
				Detector: r.name,
				Severity: r.severity,
				Confidence: r.confidence,
				Path: "commit:" + commit,
				Line: line,
				Match: redact(m),
				Message: "Potential secret found in Git history",
			})
		}
	}
	return out
}
