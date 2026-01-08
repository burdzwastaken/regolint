package evaluator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/burdzwastaken/regolint/internal/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// dangerousBuiltins lists Rego built-ins disabled for security.
var dangerousBuiltins = map[string]bool{
	"http.send":          true,
	"net.lookup_ip_addr": true,
	"opa.runtime":        true,
}

func filteredCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()

	caps.AllowNet = []string{}

	filtered := make([]*ast.Builtin, 0, len(caps.Builtins))
	for _, b := range caps.Builtins {
		if !dangerousBuiltins[b.Name] {
			filtered = append(filtered, b)
		}
	}
	caps.Builtins = filtered
	return caps
}

// Evaluator wraps OPA and manages policy lifecycle.
type Evaluator struct {
	compiler *ast.Compiler
	query    rego.PreparedEvalQuery
}

// New creates a new Evaluator with the given policies.
func New(policies map[string]string) (*Evaluator, error) {
	modules := make(map[string]*ast.Module)

	for name, content := range policies {
		parsed, err := ast.ParseModuleWithOpts(
			name,
			content,
			ast.ParserOptions{
				RegoVersion:       ast.RegoV1,
				ProcessAnnotation: true,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("parsing policy %s: %w", name, err)
		}
		modules[name] = parsed
	}

	capabilities := filteredCapabilities()
	compiler := ast.NewCompiler().
		WithStrict(true).
		WithCapabilities(capabilities)
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, fmt.Errorf("compiling policies: %v", compiler.Errors)
	}

	query, err := rego.New(
		rego.Query("data.regolint.rules[category][rule].deny"),
		rego.Compiler(compiler),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("preparing query: %w", err)
	}

	return &Evaluator{
		compiler: compiler,
		query:    query,
	}, nil
}

// Evaluate runs all policies against the given CodeContext.
func (e *Evaluator) Evaluate(ctx context.Context, input *model.CodeContext) ([]model.Violation, error) {
	return e.evaluate(ctx, input)
}

// EvaluatePackage runs all policies against the given PackageContext.
func (e *Evaluator) EvaluatePackage(ctx context.Context, input *model.PackageContext) ([]model.Violation, error) {
	return e.evaluate(ctx, input)
}

func (e *Evaluator) evaluate(ctx context.Context, input any) ([]model.Violation, error) {
	results, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluating policies: %w", err)
	}

	return e.extractViolations(results)
}

func (e *Evaluator) extractViolations(results rego.ResultSet) ([]model.Violation, error) {
	var violations []model.Violation

	for _, result := range results {
		for _, expr := range result.Expressions {
			violations = append(violations, extractFromValue(expr.Value)...)
		}
	}

	return violations, nil
}

func extractFromValue(v any) []model.Violation {
	var violations []model.Violation

	switch val := v.(type) {
	case []any:
		for _, item := range val {
			if violation, err := parseViolation(item); err == nil {
				violations = append(violations, violation)
			} else {
				violations = append(violations, extractFromValue(item)...)
			}
		}
	case map[string]any:
		if _, hasMsg := val["message"]; hasMsg {
			if violation, err := parseViolation(val); err == nil {
				violations = append(violations, violation)
				return violations
			}
		}
		for _, nested := range val {
			violations = append(violations, extractFromValue(nested)...)
		}
	}

	return violations
}

func parseViolation(v any) (model.Violation, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return model.Violation{}, errors.New("invalid violation format")
	}

	violation := model.Violation{}

	if msg, ok := m["message"].(string); ok {
		violation.Message = msg
	}
	if rule, ok := m["rule"].(string); ok {
		violation.Rule = rule
	}
	if sev, ok := m["severity"].(string); ok {
		violation.Severity = sev
	}

	if pos, ok := m["position"].(map[string]any); ok {
		if file, ok := pos["file"].(string); ok {
			violation.Position.File = file
		}
		violation.Position.Line = toInt(pos["line"])
		violation.Position.Column = toInt(pos["column"])
	}

	if fix, ok := m["fix"].(map[string]any); ok {
		violation.Fix = parseFix(fix)
	}

	return violation, nil
}

func parseFix(m map[string]any) *model.Fix {
	fix := &model.Fix{}

	if desc, ok := m["description"].(string); ok {
		fix.Description = desc
	}

	if edits, ok := m["edits"].([]any); ok {
		for _, e := range edits {
			if editMap, ok := e.(map[string]any); ok {
				edit := model.FixEdit{
					NewText: toString(editMap["new_text"]),
					OldText: toString(editMap["old_text"]),
				}
				if pos, ok := editMap["position"].(map[string]any); ok {
					edit.Position.File = toString(pos["file"])
					edit.Position.Line = toInt(pos["line"])
					edit.Position.Column = toInt(pos["column"])
				}
				fix.Edits = append(fix.Edits, edit)
			}
		}
	}

	return fix
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}
