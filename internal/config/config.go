package config

import (
	"encoding/json"
	"errors"
	"os"
)

type Config struct {
	Workers             int      `json:"workers"`
	MaxFileSize         int64    `json:"max_file_size"`
	ConfidenceThreshold int      `json:"confidence_threshold"`
	IgnorePaths         []string `json:"ignore_paths"`
	IgnoreExtensions    []string `json:"ignore_extensions"`
	DetectorPacks       []string `json:"detector_packs"`
	DisabledDetectors   []string `json:"disabled_detectors"`
	EntropyThreshold    float64  `json:"entropy_threshold"`
	CacheFile           string   `json:"cache_file"`
	BaselineFile        string   `json:"baseline_file"`
}

func Default() Config {
	return Config{Workers: 0, MaxFileSize: 10 << 20, ConfidenceThreshold: 0, EntropyThreshold: 4.2, CacheFile: ".secrethawk-cache.json", BaselineFile: ".secrethawk-baseline.json"}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		if _, err := os.Stat(".secrethawk.json"); errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		} else if err != nil {
			return cfg, err
		}
		path = ".secrethawk.json"
	}
	data, err := os.ReadFile(path)
	if err != nil { return cfg, err }
	if err := json.Unmarshal(data, &cfg); err != nil { return cfg, err }
	if cfg.MaxFileSize <= 0 { cfg.MaxFileSize = 10 << 20 }
	if cfg.EntropyThreshold <= 0 { cfg.EntropyThreshold = 4.2 }
	return cfg, nil
}
