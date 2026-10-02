package detector

import (
	"regexp"
	"strings"

	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

type Rule struct {
	Name string
	Pattern *regexp.Regexp
	Severity model.Severity
	Confidence int
}

var rules = []Rule{
	{"aws-access-key", regexp.MustCompile("\\bAKIA[0-9A-Z]{16}\\b"), model.SeverityHigh, 96},
	{"github-token", regexp.MustCompile("\\bgh[pousr]_[A-Za-z0-9_]{20,}\\b"), model.SeverityHigh, 94},
	{"google-api-key", regexp.MustCompile("\\bAIza[0-9A-Za-z_-]{35}\\b"), model.SeverityHigh, 94},
	{"slack-token", regexp.MustCompile("\\bxox[baprs]-[0-9A-Za-z-]{10,}\\b"), model.SeverityHigh, 93},
	{"private-key", regexp.MustCompile("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), model.SeverityCritical, 99},
	{"jwt", regexp.MustCompile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b"), model.SeverityMedium, 88},
	{"database-url", regexp.MustCompile("(?i)\\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis)://[^\\s\"'<>]{12,}"), model.SeverityHigh, 91},
	{"generic-secret", regexp.MustCompile("(?i)\\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret)\\s*[:=]\\s*[\"']?[A-Za-z0-9_./+=:@$-]{12,}"), model.SeverityMedium, 78},
}

func DefaultRules() []Rule { return append([]Rule(nil), rules...) }

func ScanLine(path string, lineNo int, line string) []model.Finding {
	return ScanLineWithRules(path, lineNo, line, rules)
}

func ScanLineWithRules(path string, lineNo int, line string, active []Rule) []model.Finding {
	var findings []model.Finding
	for _, r := range active {
		if m := r.Pattern.FindString(line); m != "" {
			if isPlaceholder(m) { continue }
			findings = append(findings, model.Finding{
				Detector: r.Name, Severity: r.Severity, Confidence: r.Confidence,
				Path: path, Line: lineNo, Match: redact(m),
				Message: "Potential secret detected",
			})
		}
	}
	return findings
}

func isPlaceholder(s string) bool {
	v := strings.ToLower(s)
	for _, marker := range []string{"example", "changeme", "your_", "your-", "dummy", "placeholder", "sample_secret"} {
		if strings.Contains(v, marker) { return true }
	}
	return false
}

func Redact(s string) string { return redact(s) }

func redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 { return "••••" }
	return s[:4] + "••••" + s[len(s)-4:]
}
