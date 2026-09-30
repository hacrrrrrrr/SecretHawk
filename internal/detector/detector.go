package detector

import (
  "regexp"
  "strings"
  "github.com/hacrrrrrrr/SecretHawk/internal/model"
)

type Rule struct { Name string; Pattern *regexp.Regexp; Severity model.Severity; Confidence int }

var rules = []Rule{
  {"aws-access-key", regexp.MustCompile("\\bAKIA[0-9A-Z]{16}\\b"), model.SeverityHigh, 96},
  {"github-token", regexp.MustCompile("\\bgh[pousr]_[A-Za-z0-9_]{20,}\\b"), model.SeverityHigh, 94},
  {"private-key", regexp.MustCompile("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), model.SeverityCritical, 99},
  {"jwt", regexp.MustCompile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b"), model.SeverityMedium, 88},
  {"generic-secret", regexp.MustCompile("(?i)\\b(?:api[_-]?key|secret|token|password)\\s*[:=]\\s*[A-Za-z0-9_./+=-]{12,}"), model.SeverityMedium, 78},
}

func ScanLine(path string, lineNo int, line string) []model.Finding {
  var findings []model.Finding
  for _, r := range rules {
    if r.Pattern.MatchString(line) {
      m := r.Pattern.FindString(line)
      findings = append(findings, model.Finding{Detector:r.Name, Severity:r.Severity, Confidence:r.Confidence, Path:path, Line:lineNo, Match:redact(m), Message:"Potential secret detected"})
    }
  }
  return findings
}

func redact(s string) string {
  s = strings.TrimSpace(s); if len(s) <= 8 { return "••••" }; return s[:4]+"••••"+s[len(s)-4:]
}