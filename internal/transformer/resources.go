package transformer

import (
	"go/ast"
	"strconv"
	"strings"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractResourceFacts(
	body *ast.BlockStmt,
	inFunction string,
) ([]model.ResourceInfo, []model.ResourceClose, []model.ResourceErr) {
	if body == nil {
		return []model.ResourceInfo{}, []model.ResourceClose{}, []model.ResourceErr{}
	}

	resources := make([]model.ResourceInfo, 0)
	closes := make([]model.ResourceClose, 0)
	errs := make([]model.ResourceErr, 0)

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			errs = append(errs, t.ifErrInfos(node, inFunction)...)
			return true
		case *ast.AssignStmt:
			for idx, rhs := range node.Rhs {
				target := assignmentTarget(node.Lhs, idx, len(node.Rhs), t.formatExpr)
				resources = append(resources, t.resourceInfo(rhs, target, inFunction)...)
				errs = append(errs, t.errInfo(rhs, target != "" && target != "_", inFunction)...)
			}
			return false
		case *ast.DeclStmt:
			newResources, newErrs := t.valueSpecResourceFacts(node.Decl, inFunction)
			resources = append(resources, newResources...)
			errs = append(errs, newErrs...)
			return false
		case *ast.ReturnStmt:
			for _, result := range node.Results {
				errs = append(errs, t.errInfo(result, true, inFunction)...)
			}
			return false
		case *ast.DeferStmt:
			closes = append(closes, t.deferredCloseInfos(node.Call, inFunction)...)
			return false
		case *ast.CallExpr:
			closes = append(closes, t.closeInfo(node, false, inFunction)...)
			errs = append(errs, t.errInfo(node, false, inFunction)...)
		}
		return true
	})

	return resources, closes, uniqueResourceErrs(errs)
}

func uniqueResourceErrs(errs []model.ResourceErr) []model.ResourceErr {
	seen := make(map[string]int)
	unique := make([]model.ResourceErr, 0, len(errs))
	for _, err := range errs {
		key := err.Target + ":" + strconv.Itoa(err.Position.Line) + ":" +
			strconv.Itoa(err.Position.Column)
		idx, ok := seen[key]
		if ok {
			if err.IsChecked && !unique[idx].IsChecked {
				unique[idx].IsChecked = true
			}
			continue
		}
		seen[key] = len(unique)
		unique = append(unique, err)
	}
	return unique
}

func (t *Transformer) valueSpecResourceFacts(
	decl ast.Decl,
	inFunction string,
) ([]model.ResourceInfo, []model.ResourceErr) {
	genDecl, ok := decl.(*ast.GenDecl)
	if !ok || genDecl.Tok.String() != "var" {
		return []model.ResourceInfo{}, []model.ResourceErr{}
	}

	resources := make([]model.ResourceInfo, 0, len(genDecl.Specs))
	errs := make([]model.ResourceErr, 0, len(genDecl.Specs))
	for _, spec := range genDecl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for idx, value := range valueSpec.Values {
			target := valueSpecTarget(valueSpec.Names, idx, len(valueSpec.Values))
			resources = append(resources, t.resourceInfo(value, target, inFunction)...)
			errs = append(errs, t.errInfo(value, target != "" && target != "_", inFunction)...)
		}
	}
	return resources, errs
}

func (t *Transformer) resourceInfo(expr ast.Expr, target string, inFunction string) []model.ResourceInfo {
	call, ok := expr.(*ast.CallExpr)
	if !ok || target == "" || target == "_" {
		return nil
	}

	kind, source := t.resourceKind(call, target)
	if kind == "" {
		return nil
	}

	return []model.ResourceInfo{{
		Kind:       kind,
		Target:     target,
		Source:     source,
		InFunction: inFunction,
		Position:   t.position(call.Pos()),
	}}
}

func (t *Transformer) resourceKind(call *ast.CallExpr, target string) (string, string) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}

	callee := t.formatExpr(selector)
	if isHTTPResponseCall(selector, target) {
		return "http_response", callee
	}
	if isSQLRowsCall(selector, target) {
		return "sql_rows", callee
	}
	if isSQLStmtCall(selector, target) {
		return "sql_stmt", callee
	}
	return "", ""
}

func isHTTPResponseCall(selector *ast.SelectorExpr, target string) bool {
	if !responseLikeTarget(target) {
		return false
	}
	if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == "http" {
		return selector.Sel.Name == "Get" || selector.Sel.Name == "Post" ||
			selector.Sel.Name == "Head" || selector.Sel.Name == "PostForm"
	}

	receiver := selectorReceiver(selector)
	if receiver != "client" && receiver != "http.DefaultClient" {
		return false
	}
	return selector.Sel.Name == "Do" || selector.Sel.Name == "Get" ||
		selector.Sel.Name == "Post" || selector.Sel.Name == "Head" || selector.Sel.Name == "PostForm"
}

func isSQLRowsCall(selector *ast.SelectorExpr, target string) bool {
	if !rowsLikeTarget(target) {
		return false
	}
	return selector.Sel.Name == "Query" || selector.Sel.Name == "QueryContext"
}

func isSQLStmtCall(selector *ast.SelectorExpr, target string) bool {
	if !stmtLikeTarget(target) {
		return false
	}
	return selector.Sel.Name == "Prepare" || selector.Sel.Name == "PrepareContext"
}

func selectorReceiver(selector *ast.SelectorExpr) string {
	switch x := selector.X.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return selectorReceiver(x) + "." + x.Sel.Name
	default:
		return ""
	}
}

func responseLikeTarget(target string) bool {
	lower := strings.ToLower(target)
	return lower == "resp" || lower == "response" || strings.HasPrefix(lower, "resp") ||
		strings.HasSuffix(lower, "resp") ||
		strings.HasSuffix(lower, "response")
}

func rowsLikeTarget(target string) bool {
	lower := strings.ToLower(target)
	return lower == "rows" || strings.HasSuffix(lower, "rows")
}

func stmtLikeTarget(target string) bool {
	lower := strings.ToLower(target)
	return lower == "stmt" || lower == "statement" || strings.HasSuffix(lower, "stmt")
}

func (t *Transformer) closeInfo(call *ast.CallExpr, isDefer bool, inFunction string) []model.ResourceClose {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Close" {
		return nil
	}

	return []model.ResourceClose{{
		Target:     t.formatExpr(selector.X),
		IsDefer:    isDefer,
		InFunction: inFunction,
		Position:   t.position(call.Pos()),
	}}
}

func (t *Transformer) deferredCloseInfos(call *ast.CallExpr, inFunction string) []model.ResourceClose {
	if call == nil {
		return nil
	}

	closes := t.closeInfo(call, true, inFunction)
	funcLit, ok := call.Fun.(*ast.FuncLit)
	if !ok || funcLit.Body == nil {
		return closes
	}

	ast.Inspect(funcLit.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			closes = append(closes, t.closeInfo(node, true, inFunction)...)
		}
		return true
	})
	return closes
}

func (t *Transformer) ifErrInfos(stmt *ast.IfStmt, inFunction string) []model.ResourceErr {
	errs := make([]model.ResourceErr, 0)
	if stmt.Init != nil {
		errs = append(errs, t.stmtErrInfos(stmt.Init, inFunction)...)
	}
	errs = append(errs, t.errInfo(stmt.Cond, true, inFunction)...)
	return errs
}

func (t *Transformer) stmtErrInfos(stmt ast.Stmt, inFunction string) []model.ResourceErr {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		errs := make([]model.ResourceErr, 0, len(s.Rhs))
		for idx, rhs := range s.Rhs {
			target := assignmentTarget(s.Lhs, idx, len(s.Rhs), t.formatExpr)
			errs = append(errs, t.errInfo(rhs, target != "" && target != "_", inFunction)...)
		}
		return errs
	case *ast.ExprStmt:
		return t.errInfo(s.X, false, inFunction)
	}
	return nil
}

func (t *Transformer) errInfo(expr ast.Expr, isChecked bool, inFunction string) []model.ResourceErr {
	errs := make([]model.ResourceErr, 0)
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case nil:
			return true
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			errs = append(errs, t.errCallInfo(node, isChecked, inFunction)...)
		}
		return true
	})

	return errs
}

func (t *Transformer) errCallInfo(call *ast.CallExpr, isChecked bool, inFunction string) []model.ResourceErr {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Err" {
		return nil
	}

	target := t.formatExpr(selector.X)
	if target == "" || strings.Contains(target, "(") {
		return nil
	}

	return []model.ResourceErr{{
		Target:     target,
		IsChecked:  isChecked,
		InFunction: inFunction,
		Position:   t.position(call.Pos()),
	}}
}
