package scanner

import (
	"regexp"
	"strings"

	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

var assignmentValue = regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|passwd|credential|client[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_./+=:@$-]{20,})["']?`)

func entropyFinding(path string, lineNo int, line string, threshold float64) []model.Finding {
	m := assignmentValue.FindStringSubmatch(line)
	if len(m) != 2 || strings.Contains(strings.ToLower(m[1]), "example") || strings.Contains(strings.ToLower(m[1]), "changeme") {
		return nil
	}
	if ShannonEntropy(m[1]) < threshold { return nil }
	return []model.Finding{{Detector:"high-entropy-secret", Severity:model.SeverityMedium, Confidence:82, Path:path, Line:lineNo, Match:redact(m[1]), Message:"High-entropy value associated with a secret-like key"}}
}
