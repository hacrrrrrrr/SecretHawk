package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"

	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

type Entry struct {
	Size    int64           `json:"size"`
	ModTime int64           `json:"mod_time"`
	SHA256  string          `json:"sha256"`
	ConfigKey string        `json:"config_key"`
	Findings []model.Finding `json:"findings"`
}

type Store struct {
	mu sync.Mutex
	Path string
	Entries map[string]Entry `json:"entries"`
}

func Load(path string) (*Store, error) {
	s := &Store{Path: path, Entries: map[string]Entry{}}
	if path == "" { return s, nil }
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) { return s, nil }
	if err != nil { return nil, err }
	if err := json.Unmarshal(data, s); err != nil { return nil, err }
	if s.Entries == nil { s.Entries = map[string]Entry{} }
	s.Path = path
	return s, nil
}

func (s *Store) Get(path string, size, modTime int64, configKey string) ([]model.Finding, bool) {
	s.mu.Lock(); defer s.mu.Unlock()
	e, ok := s.Entries[path]
	if !ok || e.Size != size || e.ModTime != modTime || e.ConfigKey != configKey { return nil, false }
	return append([]model.Finding(nil), e.Findings...), true
}

func (s *Store) Put(path string, size, modTime int64, configKey string, findings []model.Finding) {
	s.mu.Lock(); defer s.mu.Unlock()
	s.Entries[path] = Entry{Size:size, ModTime:modTime, ConfigKey:configKey, SHA256: hashFindings(findings), Findings:append([]model.Finding(nil), findings...)}
}

func (s *Store) Save() error {
	if s.Path == "" { return nil }
	s.mu.Lock(); defer s.mu.Unlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil { return err }
	return os.WriteFile(s.Path, append(data, '\n'), 0600)
}

func hashFindings(f []model.Finding) string {
	h := sha256.New()
	for _, x := range f { h.Write([]byte(x.Detector)); h.Write([]byte{0}); h.Write([]byte(x.Path)); h.Write([]byte{0}) }
	return hex.EncodeToString(h.Sum(nil))
}
