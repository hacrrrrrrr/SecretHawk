package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/hacrrrrrrr/SecretHawk/internal/detector"
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
			if !strings.HasPrefix(text, "+") || strings.HasPrefix(text, "+++") { continue }
			findings = append(findings, detector.ScanLine("commit:"+commit, line, strings.TrimPrefix(text, "+"))...)
		}
		if err := sc.Err(); err != nil { return findings, fmt.Errorf("history scan: %w", err) }
	}
	return Deduplicate(findings), nil
}
