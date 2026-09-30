package scanner

import "github.com/hacrrrrrrr/SecretHawk/internal/model"

func Deduplicate(findings []model.Finding) []model.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Detector + "\x00" + f.Path + "\x00" + string(rune(f.Line)) + "\x00" + f.Match
		if _, ok := seen[key]; ok { continue }
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}
