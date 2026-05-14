package transformer

import (
	"go/ast"
	"maps"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractTypeAssertions(body *ast.BlockStmt, inFunction string) []model.TypeAssertInfo {
	if body == nil {
		return nil
	}

	assertions := make([]model.TypeAssertInfo, 0)
	overrides := make(map[*ast.TypeAssertExpr]model.TypeAssertInfo)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			maps.Copy(overrides, t.extractAssignTypeAssertions(node, inFunction))
		case *ast.ValueSpec:
			maps.Copy(overrides, t.extractValueSpecTypeAssertions(node, inFunction))
		case *ast.ReturnStmt:
			for _, result := range node.Results {
				assertion, ok := result.(*ast.TypeAssertExpr)
				if ok {
					overrides[assertion] = t.typeAssertionInfo(assertion, inFunction, "return")
				}
			}
		case *ast.CallExpr:
			for _, arg := range node.Args {
				assertion, ok := arg.(*ast.TypeAssertExpr)
				if ok {
					overrides[assertion] = t.typeAssertionInfo(assertion, inFunction, "call_arg")
				}
			}
		case *ast.TypeAssertExpr:
			info, ok := overrides[node]
			if !ok {
				info = t.typeAssertionInfo(node, inFunction, "expr")
			}
			assertions = append(assertions, info)
		}

		return true
	})

	return assertions
}

func (t *Transformer) extractAssignTypeAssertions(
	stmt *ast.AssignStmt,
	inFunction string,
) map[*ast.TypeAssertExpr]model.TypeAssertInfo {
	assertions := make(map[*ast.TypeAssertExpr]model.TypeAssertInfo)
	commaOK := len(stmt.Rhs) == 1 && len(stmt.Lhs) == 2

	for _, rhs := range stmt.Rhs {
		assertion, ok := rhs.(*ast.TypeAssertExpr)
		if !ok {
			continue
		}

		info := t.typeAssertionInfo(assertion, inFunction, "assign")
		info.AssignmentTok = stmt.Tok.String()
		info.IsCommaOK = commaOK
		if commaOK {
			info.ValueTarget = t.formatExpr(stmt.Lhs[0])
			info.OKTarget = t.formatExpr(stmt.Lhs[1])
		}
		assertions[assertion] = info
	}

	return assertions
}

func (t *Transformer) extractValueSpecTypeAssertions(
	spec *ast.ValueSpec,
	inFunction string,
) map[*ast.TypeAssertExpr]model.TypeAssertInfo {
	return t.extractValueSpecTypeAssertionsWithContext(spec, inFunction, "var")
}

func (t *Transformer) extractValueSpecTypeAssertionsWithContext(
	spec *ast.ValueSpec,
	inFunction string,
	context string,
) map[*ast.TypeAssertExpr]model.TypeAssertInfo {
	assertions := make(map[*ast.TypeAssertExpr]model.TypeAssertInfo)
	commaOK := len(spec.Values) == 1 && len(spec.Names) == 2

	for _, value := range spec.Values {
		assertion, ok := value.(*ast.TypeAssertExpr)
		if !ok {
			continue
		}

		info := t.typeAssertionInfo(assertion, inFunction, context)
		info.IsCommaOK = commaOK
		if commaOK {
			info.ValueTarget = spec.Names[0].Name
			info.OKTarget = spec.Names[1].Name
		}
		assertions[assertion] = info
	}

	return assertions
}

func (t *Transformer) extractAllValueSpecTypeAssertions(
	spec *ast.ValueSpec,
	inFunction string,
	context string,
) []model.TypeAssertInfo {
	overrides := t.extractValueSpecTypeAssertionsWithContext(spec, inFunction, context)
	assertions := make([]model.TypeAssertInfo, 0, len(overrides))

	for _, value := range spec.Values {
		ast.Inspect(value, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.TypeAssertExpr:
				info, ok := overrides[node]
				if !ok {
					info = t.typeAssertionInfo(node, inFunction, context)
				}
				assertions = append(assertions, info)
			}

			return true
		})
	}

	return assertions
}

func (t *Transformer) typeAssertionInfo(
	assertion *ast.TypeAssertExpr,
	inFunction string,
	context string,
) model.TypeAssertInfo {
	assertedType := ""
	if assertion.Type != nil {
		assertedType = t.formatType(assertion.Type)
	}

	return model.TypeAssertInfo{
		Expr:         t.formatExpr(assertion.X),
		AssertedType: assertedType,
		InFunction:   inFunction,
		Context:      context,
		Position:     t.position(assertion.Pos()),
	}
}
