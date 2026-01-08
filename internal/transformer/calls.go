package transformer

import (
	"go/ast"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractCalls(fn *ast.FuncDecl, funcName string) []model.CallInfo {
	if fn.Body == nil {
		return nil
	}

	calls := make([]model.CallInfo, 0)

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		callExpr, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		call := model.CallInfo{
			InFunction: funcName,
			Position:   t.position(callExpr.Pos()),
			Args:       t.extractCallArgs(callExpr),
		}

		switch fun := callExpr.Fun.(type) {
		case *ast.Ident:
			call.Function = fun.Name
		case *ast.SelectorExpr:
			call.Function = fun.Sel.Name
			switch x := fun.X.(type) {
			case *ast.Ident:
				call.Package = x.Name
				call.Receiver = x.Name
			case *ast.CallExpr:
				call.Receiver = "call"
			case *ast.SelectorExpr:
				call.Receiver = t.formatType(x)
			}
		case *ast.FuncLit:
			call.Function = "(anonymous)"
		case *ast.ParenExpr:
			call.Function = "(conversion)"
		}

		calls = append(calls, call)
		return true
	})

	return calls
}

func (t *Transformer) extractCallArgs(call *ast.CallExpr) []string {
	args := make([]string, 0, len(call.Args))

	for _, arg := range call.Args {
		args = append(args, t.formatExpr(arg))
	}

	return args
}

func (t *Transformer) formatExpr(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.BasicLit:
		return e.Value
	case *ast.SelectorExpr:
		return t.formatExpr(e.X) + "." + e.Sel.Name
	case *ast.CallExpr:
		return t.formatExpr(e.Fun) + "(...)"
	case *ast.UnaryExpr:
		return e.Op.String() + t.formatExpr(e.X)
	case *ast.BinaryExpr:
		return t.formatExpr(e.X) + " " + e.Op.String() + " " + t.formatExpr(e.Y)
	case *ast.CompositeLit:
		return t.formatType(e.Type) + "{...}"
	case *ast.FuncLit:
		return "func(){...}"
	case *ast.IndexExpr:
		return t.formatExpr(e.X) + "[...]"
	case *ast.SliceExpr:
		return t.formatExpr(e.X) + "[:]"
	case *ast.StarExpr:
		return "*" + t.formatExpr(e.X)
	case *ast.TypeAssertExpr:
		return t.formatExpr(e.X) + ".(type)"
	default:
		return "expr"
	}
}
