// Package secrethawk exposes the public SecretHawk scanning API.
package secrethawk

import (
	"github.com/hacrrrrrrr/SecretHawk/internal/model"
	"github.com/hacrrrrrrr/SecretHawk/internal/scanner"
)

// Scan scans a file or directory and returns potential secret findings.
func Scan(path string) ([]model.Finding, error) {
	return scanner.ScanPath(path)
}
