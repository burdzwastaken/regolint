package output

import (
	"encoding/json"
	"io"

	"github.com/burdzwastaken/regolint/internal/model"
)

// SARIF format for GitHub Advanced Security integration.
// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitzero"`
}

type sarifRuleProperties struct {
	Category string `json:"category,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// WriteSARIF writes violations in SARIF format.
func WriteSARIF(w io.Writer, violations []model.Violation, version string) error {
	rules := extractRules(violations)
	results := make([]sarifResult, 0, len(violations))

	for _, v := range violations {
		var level string
		switch v.Severity {
		case "warning":
			level = "warning"
		case "info":
			level = "note"
		default:
			level = "error"
		}

		results = append(results, sarifResult{
			RuleID:  v.Rule,
			Level:   level,
			Message: sarifMessage{Text: v.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: v.Position.File},
					Region: sarifRegion{
						StartLine:   v.Position.Line,
						StartColumn: max(v.Position.Column, 1),
					},
				},
			}},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "regolint",
					Version:        version,
					InformationURI: "https://github.com/burdzwastaken/regolint",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func extractRules(violations []model.Violation) []sarifRule {
	seen := make(map[string]bool)
	var rules []sarifRule

	for _, v := range violations {
		if seen[v.Rule] {
			continue
		}
		seen[v.Rule] = true

		rules = append(rules, sarifRule{
			ID:               v.Rule,
			ShortDescription: sarifMessage{Text: v.Rule},
		})
	}

	return rules
}
