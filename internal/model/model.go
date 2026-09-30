package model

type Severity string

const (
  SeverityLow Severity = "LOW"
  SeverityMedium Severity = "MEDIUM"
  SeverityHigh Severity = "HIGH"
  SeverityCritical Severity = "CRITICAL"
)

type Finding struct {
  Detector string `json:"detector"`
  Severity Severity `json:"severity"`
  Confidence int `json:"confidence"`
  Path string `json:"path"`
  Line int `json:"line"`
  Match string `json:"match"`
  Message string `json:"message"`
}