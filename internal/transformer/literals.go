package transformer

import (
	"go/ast"
	"go/token"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractLiterals(node ast.Node, inFunction string) []model.LiteralInfo {
	if node == nil {
		return nil
	}

	literals := make([]model.LiteralInfo, 0)
	ast.Inspect(node, func(n ast.Node) bool {
		if unary, ok := n.(*ast.UnaryExpr); ok {
			lit, ok := unary.X.(*ast.BasicLit)
			if ok && isNumericLiteral(lit.Kind) && (unary.Op == token.ADD || unary.Op == token.SUB) {
				literals = append(literals, model.LiteralInfo{
					Kind:       literalKind(lit.Kind),
					Value:      unary.Op.String() + lit.Value,
					InFunction: inFunction,
					Position:   t.position(unary.Pos()),
				})
				return false
			}
		}

		lit, ok := n.(*ast.BasicLit)
		if !ok {
			return true
		}

		literals = append(literals, model.LiteralInfo{
			Kind:       literalKind(lit.Kind),
			Value:      lit.Value,
			InFunction: inFunction,
			Position:   t.position(lit.Pos()),
		})
		return true
	})

	return literals
}

func isNumericLiteral(kind token.Token) bool {
	return kind == token.INT || kind == token.FLOAT || kind == token.IMAG
}

func literalKind(kind token.Token) string {
	switch kind {
	case token.INT:
		return "int"
	case token.FLOAT:
		return "float"
	case token.IMAG:
		return "imag"
	case token.CHAR:
		return "char"
	case token.STRING:
		return "string"
	default:
		return kind.String()
	}
}
