package scanner

import (
	"sort"
	"strconv"
	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

func Deduplicate(findings []model.Finding) []model.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Detector + "\x00" + f.Path + "\x00" + strconv.Itoa(f.Line) + "\x00" + f.Match
		if _, ok := seen[key]; ok { continue }
		seen[key] = struct{}{}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path { return out[i].Path < out[j].Path }
		if out[i].Line != out[j].Line { return out[i].Line < out[j].Line }
		return out[i].Detector < out[j].Detector
	})
	return out
}
