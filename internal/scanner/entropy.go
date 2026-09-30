package scanner

import "math"

// ShannonEntropy returns the Shannon entropy of a byte string.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 { return 0 }
	var counts [256]int
	for i := 0; i < len(s); i++ { counts[s[i]]++ }
	var entropy float64
	n := float64(len(s))
	for _, c := range counts {
		if c == 0 { continue }
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
