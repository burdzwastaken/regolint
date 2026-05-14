package transformer

import (
	"go/ast"

	"github.com/burdzwastaken/regolint/internal/model"
)

const makeSliceCapArgCount = 3

func (t *Transformer) extractMakeAppendFacts(
	body *ast.BlockStmt,
	inFunction string,
) ([]model.MakeSliceInfo, []model.AppendInfo) {
	if body == nil {
		return []model.MakeSliceInfo{}, []model.AppendInfo{}
	}

	makeSlices := make([]model.MakeSliceInfo, 0)
	appends := make([]model.AppendInfo, 0)

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			for idx, rhs := range node.Rhs {
				target := assignmentTarget(node.Lhs, idx, len(node.Rhs), t.formatExpr)
				makeSlices = append(makeSlices, t.makeSliceInfo(rhs, target, inFunction)...)
				appends = append(appends, t.appendInfo(rhs, target, inFunction)...)
			}
			return false
		case *ast.DeclStmt:
			decl, ok := node.Decl.(*ast.GenDecl)
			if !ok || decl.Tok.String() != "var" {
				return false
			}

			for _, spec := range decl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for idx, value := range valueSpec.Values {
					target := valueSpecTarget(valueSpec.Names, idx, len(valueSpec.Values))
					makeSlices = append(makeSlices, t.makeSliceInfo(value, target, inFunction)...)
					appends = append(appends, t.appendInfo(value, target, inFunction)...)
				}
			}
			return false
		}

		return true
	})

	return makeSlices, appends
}

func (t *Transformer) makeSliceInfo(expr ast.Expr, target string, inFunction string) []model.MakeSliceInfo {
	call, ok := expr.(*ast.CallExpr)
	if !ok || !isIdentCall(call, "make") || len(call.Args) < 2 {
		return nil
	}

	arrayType, ok := call.Args[0].(*ast.ArrayType)
	if !ok || arrayType.Len != nil {
		return nil
	}

	info := model.MakeSliceInfo{
		Target:     target,
		LenArg:     t.formatExpr(call.Args[1]),
		InFunction: inFunction,
		Position:   t.position(call.Pos()),
	}
	if len(call.Args) >= makeSliceCapArgCount {
		info.HasCap = true
		info.CapArg = t.formatExpr(call.Args[2])
	}

	return []model.MakeSliceInfo{info}
}

func (t *Transformer) appendInfo(expr ast.Expr, target string, inFunction string) []model.AppendInfo {
	call, ok := expr.(*ast.CallExpr)
	if !ok || !isIdentCall(call, "append") || len(call.Args) == 0 {
		return nil
	}

	return []model.AppendInfo{{
		Target:     target,
		Source:     t.formatExpr(call.Args[0]),
		InFunction: inFunction,
		Position:   t.position(call.Pos()),
	}}
}

func isIdentCall(call *ast.CallExpr, name string) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == name
}

func assignmentTarget(lhs []ast.Expr, idx int, rhsCount int, format func(ast.Expr) string) string {
	if len(lhs) == rhsCount && idx < len(lhs) {
		return format(lhs[idx])
	}
	if rhsCount == 1 && len(lhs) > 0 {
		return format(lhs[0])
	}
	return ""
}

func valueSpecTarget(names []*ast.Ident, idx int, valueCount int) string {
	if len(names) == valueCount && idx < len(names) {
		return names[idx].Name
	}
	if valueCount == 1 && len(names) > 0 {
		return names[0].Name
	}
	return ""
}
