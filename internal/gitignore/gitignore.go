package gitignore

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Matcher struct {
	root string
	patterns []string
	gitRepo bool
}

func New(root string) *Matcher {
	m := &Matcher{root: root}
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil { m.gitRepo = true }
	if data, err := os.ReadFile(filepath.Join(root, ".gitignore")); err == nil {
		s := bufio.NewScanner(strings.NewReader(string(data)))
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line != "" && !strings.HasPrefix(line, "#") { m.patterns = append(m.patterns, line) }
		}
	}
	return m
}

func (m *Matcher) Ignored(path string, isDir bool) bool {
	if m.gitRepo {
		cmd := exec.Command("git", "-C", m.root, "check-ignore", "-q", "--", path)
		return cmd.Run() == nil
	}
	rel, err := filepath.Rel(m.root, path)
	if err != nil { return false }
	rel = filepath.ToSlash(rel)
	for _, p := range m.patterns {
		p = strings.TrimSuffix(strings.TrimPrefix(filepath.ToSlash(p), "/"), "/")
		if p == rel || strings.HasPrefix(rel, p+"/") || matchBase(p, rel) {
			return true
		}
	}
	return false
}

func matchBase(pattern, path string) bool {
	if !strings.Contains(pattern, "/") {
		return filepath.Base(path) == pattern
	}
	ok, _ := filepath.Match(pattern, path)
	return ok
}
