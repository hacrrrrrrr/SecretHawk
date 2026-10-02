package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

type Entry struct {
	Fingerprint string `json:"fingerprint"`
	Detector    string `json:"detector"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
}

type File struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

func Fingerprint(f model.Finding) string {
	h := sha256.Sum256([]byte(f.Detector + "\x00" + f.Path + "\x00" + f.Match))
	return hex.EncodeToString(h[:])
}

func Load(path string) (map[string]struct{}, error) {
	if path == "" { return map[string]struct{}{}, nil }
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) { return map[string]struct{}{}, nil }
	if err != nil { return nil, err }
	var file File
	if err := json.Unmarshal(data, &file); err != nil { return nil, err }
	out := make(map[string]struct{}, len(file.Entries))
	for _, e := range file.Entries {
		if strings.TrimSpace(e.Fingerprint) != "" { out[e.Fingerprint] = struct{}{} }
	}
	return out, nil
}

func Save(path string, findings []model.Finding) error {
	if path == "" { return nil }
	file := File{Version: 1, Entries: make([]Entry, 0, len(findings))}
	seen := map[string]struct{}{}
	for _, f := range findings {
		fp := Fingerprint(f)
		if _, ok := seen[fp]; ok { continue }
		seen[fp] = struct{}{}
		file.Entries = append(file.Entries, Entry{Fingerprint: fp, Detector: f.Detector, Path: f.Path, Line: f.Line})
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil { return err }
	return os.WriteFile(path, append(data, '\n'), 0600)
}
