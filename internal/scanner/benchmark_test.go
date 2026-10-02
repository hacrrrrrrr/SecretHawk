package scanner

import (
	"strings"
	"testing"
)

func BenchmarkScanPathSyntheticTree(b *testing.B) {
	root := b.TempDir()
	for i := 0; i < 200; i++ {
		name := root + "/sample-" + strings.Repeat("x", 2) + string(rune('a'+i%26)) + ".env"
		data := "NORMAL=value\nAWS_KEY=AKIA1234567890ABCDEF\n"
		if err := writeBenchmarkFile(name, data); err != nil { b.Fatal(err) }
	}
	opts := DefaultOptions()
	opts.Workers = 4
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ScanPathWithOptions(root, opts); err != nil { b.Fatal(err) }
	}
}

func writeBenchmarkFile(path, data string) error {
	return writeFile(path, data)
}
