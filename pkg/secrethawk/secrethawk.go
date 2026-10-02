// Package secrethawk exposes the public SecretHawk scanning API.
package secrethawk

import (
	"github.com/hacrrrrrrr/SecretHawk/internal/config"
	"github.com/hacrrrrrrr/SecretHawk/internal/model"
	"github.com/hacrrrrrrr/SecretHawk/internal/scanner"
)

// Scan scans a file or directory with the default scanner configuration.
func Scan(path string) ([]model.Finding, error) {
	return scanner.ScanPath(path)
}

// ScanWithConfig scans a file or directory using a JSON SecretHawk configuration file.
func ScanWithConfig(path, configPath string) ([]model.Finding, error) {
	cfg, err := config.Load(configPath)
	if err != nil { return nil, err }
	opts := scanner.DefaultOptions()
	opts.Workers = cfg.Workers
	opts.MaxFileSize = cfg.MaxFileSize
	opts.ConfidenceThreshold = cfg.ConfidenceThreshold
	opts.IgnorePaths = cfg.IgnorePaths
	opts.IgnoreExtensions = cfg.IgnoreExtensions
	opts.DisabledDetectors = cfg.DisabledDetectors
	opts.DetectorPacks = cfg.DetectorPacks
	opts.EntropyThreshold = cfg.EntropyThreshold
	return scanner.ScanPathWithOptions(path, opts)
}
