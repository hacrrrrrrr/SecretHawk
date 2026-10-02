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
	return ScanHistoryWithOptions(repo, DefaultOptions())
}

func ScanHistoryWithOptions(repo string, opts Options) ([]model.Finding, error) {
	active := detector.DefaultRules()
	packs, err := detector.LoadPacks(opts.DetectorPacks)
	if err != nil { return nil, err }
	active = detector.FilterRules(append(active, packs...), opts.DisabledDetectors)

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
			text = strings.TrimPrefix(text, "+")
			findings = append(findings, detector.ScanLineWithRules("commit:"+commit, line, text, active)...)
			if opts.EntropyThreshold > 0 { findings = append(findings, entropyFinding("commit:"+commit, line, text, opts.EntropyThreshold)...)}
		}
		if err := sc.Err(); err != nil { return findings, fmt.Errorf("history scan: %w", err) }
	}
	return filterFindings(Deduplicate(findings), opts), nil
}
