package scanner

import "testing"

func TestShannonEntropy(t *testing.T) {
	if ShannonEntropy("aaaaaaaaaaaaaaaa") >= ShannonEntropy("a8K!zP2$xQ9#mL4@") {
		t.Fatal("expected high-variation string to have higher entropy")
	}
}

func FuzzShannonEntropy(f *testing.F) {
	f.Add("hello")
	f.Add("synthetic-secret")
	f.Fuzz(func(t *testing.T, s string) {
		if ShannonEntropy(s) < 0 { t.Fatal("entropy cannot be negative") }
	})
}

func BenchmarkShannonEntropy(b *testing.B) {
	s := "a8K!zP2$xQ9#mL4@verylongsyntheticvalue"
	for i := 0; i < b.N; i++ { _ = ShannonEntropy(s) }
}
