package evaluator_test

import (
	"context"
	"testing"

	"github.com/burdzwastaken/regolint/internal/evaluator"
	"github.com/burdzwastaken/regolint/internal/model"
)

func TestEvaluatorBannedImports(t *testing.T) {
	policy := `package regolint.rules.imports.banned

deny contains violation if {
	some imp in input.imports
	imp.path == "unsafe"
	violation := {
		"message": "unsafe import not allowed",
		"position": imp.position,
		"rule": "IMP001",
	}
}
`
	eval, err := evaluator.New(map[string]string{"banned.rego": policy})
	if err != nil {
		t.Fatalf("creating evaluator: %v", err)
	}

	tests := []struct {
		name      string
		input     *model.CodeContext
		wantCount int
		wantRule  string
	}{
		{
			name: "unsafe import triggers violation",
			input: &model.CodeContext{
				Imports: []model.ImportInfo{
					{Path: "unsafe", Position: model.Position{Line: 5}},
				},
			},
			wantCount: 1,
			wantRule:  "IMP001",
		},
		{
			name: "safe import passes",
			input: &model.CodeContext{
				Imports: []model.ImportInfo{
					{Path: "fmt", Position: model.Position{Line: 5}},
				},
			},
			wantCount: 0,
		},
		{
			name: "multiple imports with one banned",
			input: &model.CodeContext{
				Imports: []model.ImportInfo{
					{Path: "fmt", Position: model.Position{Line: 5}},
					{Path: "unsafe", Position: model.Position{Line: 6}},
					{Path: "os", Position: model.Position{Line: 7}},
				},
			},
			wantCount: 1,
			wantRule:  "IMP001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := eval.Evaluate(context.Background(), tt.input)
			if err != nil {
				t.Fatalf("evaluating: %v", err)
			}

			if len(violations) != tt.wantCount {
				t.Errorf("expected %d violations, got %d", tt.wantCount, len(violations))
			}

			if tt.wantCount > 0 && len(violations) > 0 {
				if violations[0].Rule != tt.wantRule {
					t.Errorf("expected rule %q, got %q", tt.wantRule, violations[0].Rule)
				}
			}
		})
	}
}

func TestEvaluatorCredentials(t *testing.T) {
	policy := `package regolint.rules.security.credentials

deny contains violation if {
	some v in input.constants
	contains(lower(v.name), "password")
	violation := {
		"message": "hardcoded password",
		"position": v.position,
		"rule": "SEC001",
	}
}
`
	eval, err := evaluator.New(map[string]string{"credentials.rego": policy})
	if err != nil {
		t.Fatalf("creating evaluator: %v", err)
	}

	tests := []struct {
		name      string
		input     *model.CodeContext
		wantCount int
	}{
		{
			name: "password constant triggers",
			input: &model.CodeContext{
				Constants: []model.VariableInfo{
					{Name: "dbPassword", IsConst: true, Position: model.Position{Line: 10}},
				},
			},
			wantCount: 1,
		},
		{
			name: "safe constant passes",
			input: &model.CodeContext{
				Constants: []model.VariableInfo{
					{Name: "MaxRetries", IsConst: true, Position: model.Position{Line: 10}},
				},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := eval.Evaluate(context.Background(), tt.input)
			if err != nil {
				t.Fatalf("evaluating: %v", err)
			}

			if len(violations) != tt.wantCount {
				t.Errorf("expected %d violations, got %d", tt.wantCount, len(violations))
			}
		})
	}
}

func TestEvaluatorInvalidPolicy(t *testing.T) {
	_, err := evaluator.New(map[string]string{
		"invalid.rego": "this is not valid rego",
	})
	if err == nil {
		t.Error("expected error for invalid policy")
	}
}

func TestEvaluatorMultiplePolicies(t *testing.T) {
	policies := map[string]string{
		"imports.rego": `package regolint.rules.imports.banned

deny contains violation if {
	some imp in input.imports
	imp.path == "unsafe"
	violation := {"message": "unsafe", "position": imp.position, "rule": "IMP001"}
}
`,
		"naming.rego": `package regolint.rules.naming.test

deny contains violation if {
	some fn in input.functions
	fn.name == "badName"
	violation := {"message": "bad name", "position": fn.position, "rule": "NAME001"}
}
`,
	}

	eval, err := evaluator.New(policies)
	if err != nil {
		t.Fatalf("creating evaluator: %v", err)
	}

	input := &model.CodeContext{
		Imports: []model.ImportInfo{
			{Path: "unsafe", Position: model.Position{Line: 5}},
		},
		Functions: []model.FunctionInfo{
			{Name: "badName", Position: model.Position{Line: 10}},
		},
	}

	violations, err := eval.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}

	if len(violations) != 2 {
		t.Errorf("expected 2 violations from 2 policies, got %d", len(violations))
	}
}

func TestEvaluatorDangerousBuiltinsBlocked(t *testing.T) {
	tests := []struct {
		name   string
		policy string
	}{
		{
			name: "http.send is blocked",
			policy: `package regolint.rules.test.http

deny contains violation if {
	resp := http.send({"method": "GET", "url": "http://example.com"})
	violation := {"message": "test", "position": {"line": 1}, "rule": "TEST001"}
}
`,
		},
		{
			name: "opa.runtime is blocked",
			policy: `package regolint.rules.test.runtime

deny contains violation if {
	runtime := opa.runtime()
	violation := {"message": "test", "position": {"line": 1}, "rule": "TEST001"}
}
`,
		},
		{
			name: "net.lookup_ip_addr is blocked",
			policy: `package regolint.rules.test.dns

deny contains violation if {
	addrs := net.lookup_ip_addr("example.com")
	violation := {"message": "test", "position": {"line": 1}, "rule": "TEST001"}
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := evaluator.New(map[string]string{"dangerous.rego": tt.policy})
			if err == nil {
				t.Error("expected error when using dangerous builtin, got nil")
			}
		})
	}
}

func TestEvaluatorSafeBuiltinsWork(t *testing.T) {
	policy := `package regolint.rules.test.safe

deny contains violation if {
	x := concat("_", ["a", "b"])
	y := count([1, 2, 3])
	z := regex.match("foo.*", "foobar")
	x == "a_b"
	y == 3
	z == true
	violation := {"message": "test", "position": {"line": 1}, "rule": "TEST001"}
}
`
	eval, err := evaluator.New(map[string]string{"safe.rego": policy})
	if err != nil {
		t.Fatalf("safe builtins should compile: %v", err)
	}

	violations, err := eval.Evaluate(context.Background(), &model.CodeContext{})
	if err != nil {
		t.Fatalf("evaluation should succeed: %v", err)
	}

	if len(violations) != 1 {
		t.Errorf("expected 1 violation (proving rule executed), got %d", len(violations))
	}
}

func TestEvaluatorPosition(t *testing.T) {
	policy := `package regolint.rules.test.position

deny contains violation if {
	some imp in input.imports
	imp.path == "test"
	violation := {
		"message": "test",
		"position": imp.position,
		"rule": "TEST001",
	}
}
`
	eval, err := evaluator.New(map[string]string{"position.rego": policy})
	if err != nil {
		t.Fatalf("creating evaluator: %v", err)
	}

	input := &model.CodeContext{
		Imports: []model.ImportInfo{
			{
				Path: "test",
				Position: model.Position{
					File:   "test.go",
					Line:   42,
					Column: 8,
				},
			},
		},
	}

	violations, err := eval.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}

	v := violations[0]
	if v.Position.Line != 42 {
		t.Errorf("expected line 42, got %d", v.Position.Line)
	}
	if v.Position.Column != 8 {
		t.Errorf("expected column 8, got %d", v.Position.Column)
	}
}
