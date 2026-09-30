package scanner

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hacrrrrrrr/SecretHawk/internal/detector"
	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

const maxFileSize = 10 << 20

func ScanPath(root string) ([]model.Finding, error) {
	info, err := os.Stat(root)
	if err != nil { return nil, err }

	if !info.IsDir() {
		if shouldSkip(root) { return nil, nil }
		return scanFile(root)
	}

	var findings []model.Finding
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "bin", "dist", "build":
				if path != root { return filepath.SkipDir }
			}
			return nil
		}
		if shouldSkip(path) { return nil }

		f, scanErr := scanFile(path)
		if scanErr != nil {
			// Permission/race errors on individual files should not silently
			// turn a scan into a false "clean" result.
			return scanErr
		}
		findings = append(findings, f...)
		return nil
	})
	if err != nil { return nil, err }
	return Deduplicate(findings), nil
}

func scanFile(path string) ([]model.Finding, error) {
	file, err := os.Open(path)
	if err != nil { return nil, err }
	defer file.Close()

	info, err := file.Stat()
	if err != nil { return nil, err }
	if info.Size() > maxFileSize {
		return nil, fmt.Errorf("file %s exceeds maximum scan size of %d bytes", path, maxFileSize)
	}

	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)

	var findings []model.Finding
	line := 0
	for sc.Scan() {
		line++
		findings = append(findings, detector.ScanLine(path, line, sc.Text())...)
	}
	if err := sc.Err(); err != nil { return nil, err }
	return findings, nil
}

func shouldSkip(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") && base != ".env" { return true }

	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip", ".gz",
		".pdf", ".exe", ".dll", ".so", ".bin":
		return true
	}
	return false
}
