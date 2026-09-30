package output

import (
	"encoding/json"
	"io"
	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

type sarifDocument struct {
	Version string `json:"version"`
	Schema string `json:"$schema"`
	Runs []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool sarifTool `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct { Driver sarifDriver `json:"driver"` }
type sarifDriver struct { Name string `json:"name"` }
type sarifResult struct {
	RuleID string `json:"ruleId"`
	Level string `json:"level"`
	Message sarifMessage `json:"message"`
}
type sarifMessage struct { Text string `json:"text"` }

func RenderSARIF(w io.Writer, findings []model.Finding) error {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		level := "warning"
		if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
			level = "error"
		}
		results = append(results, sarifResult{
			RuleID: f.Detector,
			Level: level,
			Message: sarifMessage{Text: "Potential secret detected; value redacted."},
		})
	}
	return json.NewEncoder(w).Encode(sarifDocument{
		Version: "2.1.0",
		Schema: "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "SecretHawk"}}, Results: results}},
	})
}
