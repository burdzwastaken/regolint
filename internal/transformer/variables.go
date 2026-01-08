package transformer

import (
	"go/ast"
	"go/token"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractGenDecl(decl *ast.GenDecl, ctx *model.CodeContext) {
	switch decl.Tok {
	case token.TYPE:
		for _, spec := range decl.Specs {
			if typeSpec, ok := spec.(*ast.TypeSpec); ok {
				typeInfo := t.extractType(typeSpec, decl.Doc)
				ctx.Types = append(ctx.Types, typeInfo)
			}
		}
	case token.VAR:
		for _, spec := range decl.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				vars := t.extractVariables(valueSpec, false)
				ctx.Variables = append(ctx.Variables, vars...)
			}
		}
	case token.CONST:
		for _, spec := range decl.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				consts := t.extractVariables(valueSpec, true)
				ctx.Constants = append(ctx.Constants, consts...)
			}
		}
	}
}

func (t *Transformer) extractVariables(spec *ast.ValueSpec, isConst bool) []model.VariableInfo {
	vars := make([]model.VariableInfo, 0, len(spec.Names))

	var typeStr string
	if spec.Type != nil {
		typeStr = t.formatType(spec.Type)
	}

	for i, name := range spec.Names {
		v := model.VariableInfo{
			Name:       name.Name,
			Type:       typeStr,
			IsExported: isExported(name.Name),
			IsConst:    isConst,
			Position:   t.position(name.Pos()),
		}

		if i < len(spec.Values) {
			v.Value = t.formatExpr(spec.Values[i])
		}

		vars = append(vars, v)
	}

	return vars
}
