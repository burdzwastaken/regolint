package transformer

import (
	"go/ast"
	"go/token"
	"maps"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractRangeLoopFacts(
	body *ast.BlockStmt,
	inFunction string,
) ([]model.RangeLoopInfo, []model.LoopVarCopyInfo) {
	if body == nil {
		return []model.RangeLoopInfo{}, []model.LoopVarCopyInfo{}
	}

	rangeLoops := make([]model.RangeLoopInfo, 0)
	loopVarCopies := make([]model.LoopVarCopyInfo, 0)

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.RangeStmt:
			position := t.position(node.Pos())
			loop := model.RangeLoopInfo{
				Key:        loopVarName(node.Key),
				Value:      loopVarName(node.Value),
				Source:     t.formatExpr(node.X),
				InFunction: inFunction,
				EndLine:    t.position(node.Body.Rbrace).Line,
				Position:   position,
			}
			rangeLoops = append(rangeLoops, loop)
			loopVars := rangeLoopVars(loop)
			loopVarCopies = append(loopVarCopies, t.extractLoopVarCopies(node.Body, inFunction, loopVars)...)
		}
		return true
	})

	return rangeLoops, loopVarCopies
}

func (t *Transformer) extractLoopVarCopies(
	body *ast.BlockStmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	if body == nil {
		return []model.LoopVarCopyInfo{}
	}
	return t.extractLoopVarCopiesFromStmts(body.List, inFunction, cloneLoopVars(loopVars))
}

// nolint:gocyclo
func (t *Transformer) extractLoopVarCopiesFromStmts(
	stmts []ast.Stmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	copies := make([]model.LoopVarCopyInfo, 0, len(stmts))

	for _, stmt := range stmts {
		switch node := stmt.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				copies = append(copies, t.loopVarCopiesFromAssign(node, inFunction, loopVars)...)
				shadowAssignTargets(node, loopVars)
			}
		case *ast.DeclStmt:
			copies = append(copies, t.loopVarCopiesFromDecl(node, inFunction, loopVars)...)
			shadowDeclTargets(node, loopVars)
		case *ast.BlockStmt:
			copies = append(copies, t.extractLoopVarCopiesFromStmts(
				node.List,
				inFunction,
				cloneLoopVars(loopVars),
			)...)
		case *ast.IfStmt:
			copies = append(copies, t.loopVarCopiesFromIf(node, inFunction, loopVars)...)
		case *ast.ForStmt:
			copies = append(copies, t.loopVarCopiesFromFor(node, inFunction, loopVars)...)
		case *ast.SwitchStmt:
			copies = append(copies, t.loopVarCopiesFromSwitch(node, inFunction, loopVars)...)
		case *ast.TypeSwitchStmt:
			copies = append(copies, t.loopVarCopiesFromTypeSwitch(node, inFunction, loopVars)...)
		case *ast.SelectStmt:
			copies = append(copies, t.loopVarCopiesFromSelect(node, inFunction, loopVars)...)
		case *ast.RangeStmt:
			// Nested range loops are extracted separately by the outer AST walk.
			continue
		}
	}

	return copies
}

func (t *Transformer) loopVarCopiesFromIf(
	stmt *ast.IfStmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	scoped := cloneLoopVars(loopVars)
	copies := t.loopVarCopiesFromOptionalStmt(stmt.Init, inFunction, scoped)
	copies = append(copies, t.extractLoopVarCopiesFromStmts(
		stmt.Body.List,
		inFunction,
		cloneLoopVars(scoped),
	)...)
	if stmt.Else != nil {
		copies = append(copies, t.loopVarCopiesFromNestedStmt(stmt.Else, inFunction, cloneLoopVars(scoped))...)
	}
	return copies
}

func (t *Transformer) loopVarCopiesFromFor(
	stmt *ast.ForStmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	scoped := cloneLoopVars(loopVars)
	copies := t.loopVarCopiesFromOptionalStmt(stmt.Init, inFunction, scoped)
	copies = append(copies, t.extractLoopVarCopiesFromStmts(stmt.Body.List, inFunction, scoped)...)
	return copies
}

func (t *Transformer) loopVarCopiesFromSwitch(
	stmt *ast.SwitchStmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	scoped := cloneLoopVars(loopVars)
	copies := t.loopVarCopiesFromOptionalStmt(stmt.Init, inFunction, scoped)
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CaseClause)
		if ok {
			copies = append(copies, t.extractLoopVarCopiesFromStmts(clause.Body, inFunction, cloneLoopVars(scoped))...)
		}
	}
	return copies
}

func (t *Transformer) loopVarCopiesFromTypeSwitch(
	stmt *ast.TypeSwitchStmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	scoped := cloneLoopVars(loopVars)
	copies := t.loopVarCopiesFromOptionalStmt(stmt.Init, inFunction, scoped)
	copies = append(copies, t.loopVarCopiesFromOptionalStmt(stmt.Assign, inFunction, scoped)...)
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CaseClause)
		if ok {
			copies = append(copies, t.extractLoopVarCopiesFromStmts(clause.Body, inFunction, cloneLoopVars(scoped))...)
		}
	}
	return copies
}

func (t *Transformer) loopVarCopiesFromSelect(
	stmt *ast.SelectStmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	copies := make([]model.LoopVarCopyInfo, 0, len(stmt.Body.List))
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CommClause)
		if ok {
			scoped := cloneLoopVars(loopVars)
			copies = append(copies, t.loopVarCopiesFromOptionalStmt(clause.Comm, inFunction, scoped)...)
			copies = append(copies, t.extractLoopVarCopiesFromStmts(clause.Body, inFunction, scoped)...)
		}
	}
	return copies
}

func (t *Transformer) loopVarCopiesFromNestedStmt(
	stmt ast.Stmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	switch node := stmt.(type) {
	case *ast.BlockStmt:
		return t.extractLoopVarCopiesFromStmts(node.List, inFunction, cloneLoopVars(loopVars))
	case *ast.IfStmt:
		return t.loopVarCopiesFromIf(node, inFunction, loopVars)
	default:
		return []model.LoopVarCopyInfo{}
	}
}

func (t *Transformer) loopVarCopiesFromOptionalStmt(
	stmt ast.Stmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	if stmt == nil {
		return []model.LoopVarCopyInfo{}
	}
	switch node := stmt.(type) {
	case *ast.AssignStmt:
		copies := make([]model.LoopVarCopyInfo, 0)
		if node.Tok == token.DEFINE {
			copies = append(copies, t.loopVarCopiesFromAssign(node, inFunction, loopVars)...)
			shadowAssignTargets(node, loopVars)
		}
		return copies
	case *ast.DeclStmt:
		copies := t.loopVarCopiesFromDecl(node, inFunction, loopVars)
		shadowDeclTargets(node, loopVars)
		return copies
	default:
		return []model.LoopVarCopyInfo{}
	}
}

func (t *Transformer) loopVarCopiesFromAssign(
	stmt *ast.AssignStmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	copies := make([]model.LoopVarCopyInfo, 0, len(stmt.Lhs))

	for idx, lhs := range stmt.Lhs {
		if idx >= len(stmt.Rhs) {
			continue
		}
		copyInfo, ok := t.loopVarCopyInfo(lhs, stmt.Rhs[idx], inFunction, loopVars)
		if ok {
			copies = append(copies, copyInfo)
		}
	}

	return copies
}

func (t *Transformer) loopVarCopiesFromDecl(
	stmt *ast.DeclStmt,
	inFunction string,
	loopVars map[string]string,
) []model.LoopVarCopyInfo {
	decl, ok := stmt.Decl.(*ast.GenDecl)
	if !ok || decl.Tok != token.VAR {
		return []model.LoopVarCopyInfo{}
	}

	copies := make([]model.LoopVarCopyInfo, 0, len(decl.Specs))
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for idx, name := range valueSpec.Names {
			if idx >= len(valueSpec.Values) {
				continue
			}
			copyInfo, ok := t.loopVarCopyInfo(name, valueSpec.Values[idx], inFunction, loopVars)
			if ok {
				copies = append(copies, copyInfo)
			}
		}
	}

	return copies
}

func (t *Transformer) loopVarCopyInfo(
	target ast.Expr,
	value ast.Expr,
	inFunction string,
	loopVars map[string]string,
) (model.LoopVarCopyInfo, bool) {
	targetName := loopVarName(target)
	valueName := loopVarName(value)
	if targetName == "" || targetName != valueName {
		return model.LoopVarCopyInfo{}, false
	}

	kind, ok := loopVars[targetName]
	if !ok {
		return model.LoopVarCopyInfo{}, false
	}

	return model.LoopVarCopyInfo{
		Variable:   targetName,
		Kind:       kind,
		InFunction: inFunction,
		Position:   t.position(target.Pos()),
	}, true
}

func rangeLoopVars(loop model.RangeLoopInfo) map[string]string {
	vars := make(map[string]string)
	if loop.Key != "" {
		vars[loop.Key] = "key"
	}
	if loop.Value != "" {
		vars[loop.Value] = "value"
	}
	return vars
}

func cloneLoopVars(loopVars map[string]string) map[string]string {
	cloned := make(map[string]string, len(loopVars))
	maps.Copy(cloned, loopVars)
	return cloned
}

func shadowAssignTargets(stmt *ast.AssignStmt, loopVars map[string]string) {
	for _, lhs := range stmt.Lhs {
		delete(loopVars, loopVarName(lhs))
	}
}

func shadowDeclTargets(stmt *ast.DeclStmt, loopVars map[string]string) {
	decl, ok := stmt.Decl.(*ast.GenDecl)
	if !ok || decl.Tok != token.VAR {
		return
	}
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, name := range valueSpec.Names {
			delete(loopVars, name.Name)
		}
	}
}

func loopVarName(expr ast.Expr) string {
	ident, ok := expr.(*ast.Ident)
	if !ok || ident.Name == "_" {
		return ""
	}
	return ident.Name
}
