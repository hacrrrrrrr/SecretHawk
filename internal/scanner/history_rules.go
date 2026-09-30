package scanner

import (
	"regexp"
	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

var historyRules = []struct {
	name string
	re *regexp.Regexp
	severity model.Severity
	confidence int
}{
	{"aws-access-key", regexp.MustCompile("\\bAKIA[0-9A-Z]{16}\\b"), model.SeverityHigh, 96},
	{"github-token", regexp.MustCompile("\\bgh[pousr]_[A-Za-z0-9_]{20,}\\b"), model.SeverityHigh, 94},
	{"private-key", regexp.MustCompile("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), model.SeverityCritical, 99},
	{"jwt", regexp.MustCompile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b"), model.SeverityMedium, 88},
}
