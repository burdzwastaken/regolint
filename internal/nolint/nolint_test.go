package nolint

import (
	"go/parser"
	"go/token"
	"testing"
)

func TestParseComment(t *testing.T) {
	tests := []struct {
		name      string
		comment   string
		wantMatch bool
		wantRules []string
	}{
		{
			name:      "simple nolint",
			comment:   "//nolint",
			wantMatch: true,
			wantRules: nil,
		},
		{
			name:      "nolint with space",
			comment:   "// nolint",
			wantMatch: true,
			wantRules: nil,
		},
		{
			name:      "nolint with single rule",
			comment:   "//nolint:TAG001",
			wantMatch: true,
			wantRules: []string{"TAG001"},
		},
		{
			name:      "nolint with multiple rules",
			comment:   "//nolint:TAG001,ERR002",
			wantMatch: true,
			wantRules: []string{"TAG001", "ERR002"},
		},
		{
			name:      "nolint with reason",
			comment:   "//nolint:TAG001 // uses mapstructure instead",
			wantMatch: true,
			wantRules: []string{"TAG001"},
		},
		{
			name:      "regular comment",
			comment:   "// this is a comment",
			wantMatch: false,
			wantRules: nil,
		},
		{
			name:      "comment mentioning nolint",
			comment:   "// see nolint docs",
			wantMatch: false,
			wantRules: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := "package foo\n" + tt.comment + "\nvar x int\n"
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			directives := Extract(fset, file)

			if tt.wantMatch {
				if len(directives) != 1 {
					t.Fatalf("expected 1 directive, got %d", len(directives))
				}
				d := directives[0]
				if len(d.Rules) != len(tt.wantRules) {
					t.Fatalf("expected %d rules, got %d", len(tt.wantRules), len(d.Rules))
				}
				for i, r := range tt.wantRules {
					if d.Rules[i] != r {
						t.Errorf("rule %d: expected %q, got %q", i, r, d.Rules[i])
					}
				}
			} else if len(directives) != 0 {
				t.Fatalf("expected no directives, got %d", len(directives))
			}
		})
	}
}

func TestDirective_Match(t *testing.T) {
	tests := []struct {
		name   string
		rules  []string
		check  string
		expect bool
	}{
		{
			name:   "empty rules matches all",
			rules:  nil,
			check:  "TAG001",
			expect: true,
		},
		{
			name:   "specific rule matches",
			rules:  []string{"TAG001"},
			check:  "TAG001",
			expect: true,
		},
		{
			name:   "specific rule no match",
			rules:  []string{"TAG001"},
			check:  "ERR002",
			expect: false,
		},
		{
			name:   "multiple rules match",
			rules:  []string{"TAG001", "ERR002"},
			check:  "ERR002",
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Directive{Rules: tt.rules}
			if got := d.Match(tt.check); got != tt.expect {
				t.Errorf("Match(%q) = %v, want %v", tt.check, got, tt.expect)
			}
		})
	}
}
