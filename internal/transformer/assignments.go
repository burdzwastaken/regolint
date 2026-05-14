package transformer

import (
	"go/ast"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractBlankAssignments(body *ast.BlockStmt, inFunction string) []model.BlankAssignInfo {
	if body == nil {
		return nil
	}

	assignments := make([]model.BlankAssignInfo, 0)
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}

		stmt, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		blankCount := 0
		for _, expr := range stmt.Lhs {
			ident, ok := expr.(*ast.Ident)
			if ok && ident.Name == "_" {
				blankCount++
			}
		}

		if blankCount > 0 {
			assignments = append(assignments, model.BlankAssignInfo{
				BlankCount: blankCount,
				TotalCount: len(stmt.Lhs),
				InFunction: inFunction,
				Position:   t.position(stmt.Pos()),
			})
		}

		return true
	})

	return assignments
}
