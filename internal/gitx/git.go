package gitx

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func IsURL(target string) bool {
	return strings.HasPrefix(target, "https://") ||
		strings.HasPrefix(target, "http://") ||
		strings.HasPrefix(target, "git@") ||
		strings.HasPrefix(target, "ssh://")
}

func Prepare(target string) (string, func(), error) {
	if !IsURL(target) {
		abs, err := filepath.Abs(target)
		if err != nil { return "", func(){}, err }
		if _, err := os.Stat(abs); err != nil { return "", func(){}, err }
		return abs, func(){}, nil
	}

	dir, err := os.MkdirTemp("", "secrethawk-*")
	if err != nil { return "", func(){}, err }

	cmd := exec.Command("git", "clone", "--quiet", "--no-tags", target, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		return "", func(){}, fmt.Errorf("git clone failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return dir, func(){ _ = os.RemoveAll(dir) }, nil
}

func History(target string) ([]string, error) {
	cmd := exec.Command("git", "-C", target, "log", "--all", "--format=%H")
	out, err := cmd.Output()
	if err != nil { return nil, err }
	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	if len(lines) == 1 && len(lines[0]) == 0 { return nil, nil }
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(line) > 0 { result = append(result, string(line)) }
	}
	return result, nil
}

func ShowCommit(target, commit string) ([]byte, error) {
	cmd := exec.Command("git", "-C", target, "show", "--format=", "--unified=0", "--binary", commit)
	return cmd.Output()
}
