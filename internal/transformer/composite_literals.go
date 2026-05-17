package transformer

import (
	"go/ast"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractPackageCompositeLiterals(file *ast.File) []model.CompositeLiteralInfo {
	return t.extractCompositeLiterals(file, "", func(n ast.Node) bool {
		_, isFuncDecl := n.(*ast.FuncDecl)
		return isFuncDecl
	})
}

func (t *Transformer) extractFunctionCompositeLiterals(node ast.Node, inFunction string) []model.CompositeLiteralInfo {
	return t.extractCompositeLiterals(node, inFunction, func(n ast.Node) bool {
		_, isFuncLit := n.(*ast.FuncLit)
		return isFuncLit
	})
}

func (t *Transformer) extractCompositeLiterals(
	node ast.Node,
	inFunction string,
	shouldSkip func(ast.Node) bool,
) []model.CompositeLiteralInfo {
	if node == nil {
		return nil
	}

	literals := make([]model.CompositeLiteralInfo, 0)
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		if shouldSkip != nil && shouldSkip(n) {
			return false
		}

		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}

		literals = append(literals, t.compositeLiteralInfo(lit, inFunction))
		return true
	})

	return literals
}

func (t *Transformer) compositeLiteralInfo(lit *ast.CompositeLit, inFunction string) model.CompositeLiteralInfo {
	return model.CompositeLiteralInfo{
		Type:         t.formatType(lit.Type),
		TypeIdentity: t.typeIdentity(lit.Type),
		TypeRef:      t.typeRef(lit.Type),
		TypeKind:     compositeLiteralTypeKind(lit.Type),
		Fields:       compositeLiteralFields(lit),
		InFunction:   inFunction,
		Position:     t.position(lit.Pos()),
	}
}

func compositeLiteralTypeKind(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.ArrayType:
		if e.Len == nil {
			return "slice"
		}
		return "array"
	case *ast.MapType:
		return "map"
	case *ast.StructType:
		return "struct"
	case *ast.StarExpr:
		return compositeLiteralTypeKind(e.X)
	default:
		return "unknown"
	}
}

func compositeLiteralFields(lit *ast.CompositeLit) []string {
	fields := make([]string, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}

		if ident, ok := kv.Key.(*ast.Ident); ok {
			fields = append(fields, ident.Name)
		}
	}
	return fields
}
