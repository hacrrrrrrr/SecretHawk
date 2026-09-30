package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanPathFindsRedactedSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.txt")
	secret := "AKIA1234567890ABCDEF"
	if err := os.WriteFile(path, []byte("key="+secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanPath(dir)
	if err != nil { t.Fatal(err) }
	if len(findings) != 1 { t.Fatalf("got %d findings, want 1", len(findings)) }
	if findings[0].Match == secret || findings[0].Match == "" {
		t.Fatalf("secret was not safely redacted: %q", findings[0].Match)
	}
	if findings[0].Line != 1 { t.Fatalf("got line %d, want 1", findings[0].Line) }
}

func TestScanPathSkipsGitDirectory(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.Mkdir(gitDir, 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte("AKIA1234567890ABCDEF"), 0600); err != nil { t.Fatal(err) }

	findings, err := ScanPath(dir)
	if err != nil { t.Fatal(err) }
	if len(findings) != 0 { t.Fatalf("found secret inside excluded .git directory") }
}
