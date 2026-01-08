package config

import (
	"testing"
)

func TestShouldSkip(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		filePath string
		want     bool
	}{
		{
			name:     "exact match",
			patterns: []string{"vendor/foo.go"},
			filePath: "vendor/foo.go",
			want:     true,
		},
		{
			name:     "single star",
			patterns: []string{"*.go"},
			filePath: "foo.go",
			want:     true,
		},
		{
			name:     "double star recursive",
			patterns: []string{"**/vendor/**"},
			filePath: "src/pkg/vendor/lib/file.go",
			want:     true,
		},
		{
			name:     "double star test files",
			patterns: []string{"**/*_test.go"},
			filePath: "internal/pkg/foo_test.go",
			want:     true,
		},
		{
			name:     "no match",
			patterns: []string{"**/vendor/**"},
			filePath: "src/pkg/lib/file.go",
			want:     false,
		},
		{
			name:     "multiple patterns first matches",
			patterns: []string{"**/*_test.go", "**/vendor/**"},
			filePath: "pkg/foo_test.go",
			want:     true,
		},
		{
			name:     "multiple patterns second matches",
			patterns: []string{"**/*_test.go", "**/vendor/**"},
			filePath: "vendor/lib.go",
			want:     true,
		},
		{
			name:     "generated files",
			patterns: []string{"**/generated/**", "**/*.gen.go"},
			filePath: "api/generated/types.go",
			want:     true,
		},
		{
			name:     "mock files",
			patterns: []string{"**/mock_*.go"},
			filePath: "internal/mock_client.go",
			want:     true,
		},
		{
			name:     "empty patterns",
			patterns: []string{},
			filePath: "any/file.go",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Exclude: tt.patterns}
			got := cfg.ShouldSkip(tt.filePath)
			if got != tt.want {
				t.Errorf("ShouldSkip(%q) with patterns %v = %v, want %v",
					tt.filePath, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestIsRuleDisabled(t *testing.T) {
	tests := []struct {
		name     string
		disabled []string
		rule     string
		want     bool
	}{
		{
			name:     "rule disabled",
			disabled: []string{"SEC001", "NAME001"},
			rule:     "SEC001",
			want:     true,
		},
		{
			name:     "rule not disabled",
			disabled: []string{"SEC001", "NAME001"},
			rule:     "TAG001",
			want:     false,
		},
		{
			name:     "empty disabled list",
			disabled: []string{},
			rule:     "SEC001",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Rules.Disabled = tt.disabled
			got := cfg.IsRuleDisabled(tt.rule)
			if got != tt.want {
				t.Errorf("IsRuleDisabled(%q) = %v, want %v", tt.rule, got, tt.want)
			}
		})
	}
}
