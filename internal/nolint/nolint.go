package nolint

import (
	"go/ast"
	"go/token"
	"regexp"
	"slices"
	"strings"
)

// Directive represents a nolint directive on a specific line.
type Directive struct {
	Line    int      `json:"line"`
	EndLine int      `json:"end_line,omitempty"`
	Rules   []string `json:"rules,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

// Match returns true if this directive applies to the given rule.
func (d Directive) Match(rule string) bool {
	if len(d.Rules) == 0 {
		return true // empty rules matches all
	}
	return slices.Contains(d.Rules, rule)
}

// nolintPattern matches // nolint or // nolint:RULE1,RULE2 with optional reason.
var nolintPattern = regexp.MustCompile(`//\s*nolint(?::([A-Za-z0-9_,]+))?(?:\s+//\s*(.+))?`)

// Extract parses all nolint directives from a file's comments.
func Extract(fset *token.FileSet, file *ast.File) []Directive {
	var directives []Directive

	structScopes := make(map[int]int)
	ast.Inspect(file, func(n ast.Node) bool {
		if ts, ok := n.(*ast.TypeSpec); ok {
			if _, isStruct := ts.Type.(*ast.StructType); isStruct {
				startLine := fset.Position(ts.Pos()).Line
				endLine := fset.Position(ts.End()).Line
				structScopes[startLine-1] = endLine
			}
		}
		return true
	})

	for _, cg := range file.Comments {
		for _, c := range cg.List {
			if d, ok := parseComment(fset, c); ok {
				if endLine, isStructScope := structScopes[d.Line]; isStructScope {
					d.EndLine = endLine
				}
				directives = append(directives, d)
			}
		}
	}

	return directives
}

func parseComment(fset *token.FileSet, c *ast.Comment) (Directive, bool) {
	text := c.Text

	matches := nolintPattern.FindStringSubmatch(text)
	if matches == nil {
		return Directive{}, false
	}

	d := Directive{
		Line: fset.Position(c.Pos()).Line,
	}

	if matches[1] != "" {
		for rule := range strings.SplitSeq(matches[1], ",") {
			rule = strings.TrimSpace(rule)
			if rule != "" {
				d.Rules = append(d.Rules, rule)
			}
		}
	}

	if matches[2] != "" {
		d.Reason = strings.TrimSpace(matches[2])
	}

	return d, true
}

// Filter removes violations that are suppressed by nolint directives.
func Filter(violations []Violation, directives []Directive) []Violation {
	if len(directives) == 0 {
		return violations
	}

	lineMap := make(map[int][]Directive)
	for _, d := range directives {
		lineMap[d.Line] = append(lineMap[d.Line], d)
	}

	var filtered []Violation
	for _, v := range violations {
		if !isSuppressed(v, lineMap, directives) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// Violation interface for filtering - matches model.Violation shape.
type Violation interface {
	GetRule() string
	GetLine() int
}

func isSuppressed(v Violation, lineMap map[int][]Directive, allDirectives []Directive) bool {
	line := v.GetLine()

	for _, checkLine := range []int{line, line - 1} {
		directives, ok := lineMap[checkLine]
		if !ok {
			continue
		}
		for _, d := range directives {
			if d.Match(v.GetRule()) {
				return true
			}
		}
	}

	for _, d := range allDirectives {
		if d.EndLine > 0 && line > d.Line && line <= d.EndLine {
			if d.Match(v.GetRule()) {
				return true
			}
		}
	}

	return false
}
