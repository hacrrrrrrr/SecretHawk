// Package detector contains public detector metadata types.
package detector

// Severity describes the relative urgency of a finding.
type Severity string

const (
	Low Severity = "LOW"
	Medium Severity = "MEDIUM"
	High Severity = "HIGH"
	Critical Severity = "CRITICAL"
)
