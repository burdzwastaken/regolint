package transformer

import (
	"go/ast"
	"strconv"
	"strings"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractSubtests(body *ast.BlockStmt, inFunction string) []model.SubtestInfo {
	if body == nil {
		return []model.SubtestInfo{}
	}

	subtests := make([]model.SubtestInfo, 0)
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		subtest, ok := t.subtestInfo(call, inFunction)
		if ok {
			subtests = append(subtests, subtest)
		}
		return true
	})

	return subtests
}

func (t *Transformer) subtestInfo(call *ast.CallExpr, inFunction string) (model.SubtestInfo, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Run" || len(call.Args) < 2 {
		return model.SubtestInfo{}, false
	}

	funcLit, ok := call.Args[1].(*ast.FuncLit)
	if !ok || funcLit.Body == nil {
		return model.SubtestInfo{}, false
	}

	testParam := t.subtestParam(funcLit)
	if testParam == "" {
		return model.SubtestInfo{}, false
	}

	return model.SubtestInfo{
		Name:        subtestName(call.Args[0]),
		Function:    inFunction,
		TestParam:   testParam,
		HasParallel: subtestHasParallel(funcLit.Body, testParam),
		Position:    t.position(call.Pos()),
	}, true
}

func (t *Transformer) subtestParam(fn *ast.FuncLit) string {
	if fn.Type == nil || fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return ""
	}

	param := fn.Type.Params.List[0]
	if len(param.Names) == 0 || t.formatType(param.Type) != "*testing.T" {
		return ""
	}
	return param.Names[0].Name
}

func subtestName(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return ""
	}
	name, err := strconv.Unquote(lit.Value)
	if err != nil {
		return strings.Trim(lit.Value, "`\"")
	}
	return name
}

func subtestHasParallel(body *ast.BlockStmt, testParam string) bool {
	hasParallel := false
	ast.Inspect(body, func(n ast.Node) bool {
		if hasParallel {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			selector, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Parallel" {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if ok && ident.Name == testParam {
				hasParallel = true
				return false
			}
		}
		return true
	})
	return hasParallel
}
