package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

type Pack struct {
	Name  string `json:"name"`
	Rules []PackRule `json:"rules"`
}

type PackRule struct {
	Name string `json:"name"`
	Pattern string `json:"pattern"`
	Severity model.Severity `json:"severity"`
	Confidence int `json:"confidence"`
}

func LoadPacks(paths []string) ([]Rule, error) {
	var out []Rule
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil { return nil, err }
		var pack Pack
		if err := json.Unmarshal(data, &pack); err != nil { return nil, fmt.Errorf("detector pack %s: %w", path, err) }
		for _, p := range pack.Rules {
			if p.Name == "" || p.Pattern == "" { return nil, fmt.Errorf("invalid detector pack rule in %s", path) }
			re, err := regexp.Compile(p.Pattern)
			if err != nil { return nil, fmt.Errorf("detector %s: %w", p.Name, err) }
			if p.Confidence <= 0 { p.Confidence = 80 }
			out = append(out, Rule{Name:p.Name, Pattern:re, Severity:p.Severity, Confidence:p.Confidence})
		}
	}
	return out, nil
}

func FilterRules(rules []Rule, disabled []string) []Rule {
	if len(disabled) == 0 { return rules }
	skip := map[string]struct{}{}
	for _, n := range disabled { skip[strings.TrimSpace(n)] = struct{}{} }
	out := make([]Rule, 0, len(rules))
	for _, r := range rules { if _, ok := skip[r.Name]; !ok { out = append(out, r) } }
	return out
}
