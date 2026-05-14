package transformer

import (
	"go/ast"
	"go/token"

	"github.com/burdzwastaken/regolint/internal/model"
)

// nolint:gocyclo,funlen
func (t *Transformer) extractGenDecl(decl *ast.GenDecl, ctx *model.CodeContext) {
	blockID := len(ctx.DeclGroups) + 1
	ctx.DeclGroups = append(ctx.DeclGroups, model.DeclGroupInfo{
		Kind:      decl.Tok.String(),
		Count:     declSpecCount(decl),
		IsGrouped: decl.Lparen.IsValid(),
		BlockID:   blockID,
		Position:  t.position(decl.Pos()),
	})

	switch decl.Tok {
	case token.IMPORT:
		for _, spec := range decl.Specs {
			if importSpec, ok := spec.(*ast.ImportSpec); ok {
				name := ""
				if importSpec.Name != nil {
					name = importSpec.Name.Name
				} else if importSpec.Path != nil {
					name = importSpec.Path.Value
				}
				ctx.Declarations = append(ctx.Declarations, model.DeclInfo{
					Kind:     "import",
					Name:     name,
					Position: t.position(importSpec.Pos()),
				})
			}
		}
	case token.TYPE:
		for _, spec := range decl.Specs {
			if typeSpec, ok := spec.(*ast.TypeSpec); ok {
				typeInfo := t.extractType(typeSpec, decl.Doc)
				ctx.Types = append(ctx.Types, typeInfo)
				ctx.Declarations = append(ctx.Declarations, model.DeclInfo{
					Kind:     "type",
					Name:     typeSpec.Name.Name,
					Position: t.position(typeSpec.Pos()),
				})
			}
		}
	case token.VAR:
		for _, spec := range decl.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				vars := t.extractVariables(valueSpec, false, blockID, nil)
				ctx.Variables = append(ctx.Variables, vars...)
				ctx.TypeAssertions = append(ctx.TypeAssertions, t.extractAllValueSpecTypeAssertions(valueSpec, "", "var")...)
				for _, variable := range vars {
					ctx.Declarations = append(ctx.Declarations, model.DeclInfo{
						Kind:     "var",
						Name:     variable.Name,
						Position: variable.Position,
					})
				}
			}
		}
	case token.CONST:
		var previousUsesIota []bool
		for _, spec := range decl.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				usesIota := valueSpecUsesIota(valueSpec, previousUsesIota)
				consts := t.extractVariables(valueSpec, true, blockID, usesIota)
				ctx.Constants = append(ctx.Constants, consts...)
				ctx.TypeAssertions = append(ctx.TypeAssertions, t.extractAllValueSpecTypeAssertions(valueSpec, "", "const")...)
				for _, constant := range consts {
					ctx.Declarations = append(ctx.Declarations, model.DeclInfo{
						Kind:     "const",
						Name:     constant.Name,
						Position: constant.Position,
					})
				}
				previousUsesIota = usesIota
			}
		}
	}
}

func (t *Transformer) extractVariables(
	spec *ast.ValueSpec,
	isConst bool,
	blockID int,
	usesIota []bool,
) []model.VariableInfo {
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
			BlockID:    blockID,
			Position:   t.position(name.Pos()),
		}
		if i < len(usesIota) {
			v.UsesIota = usesIota[i]
		}

		if i < len(spec.Values) {
			v.Value = t.formatExpr(spec.Values[i])
		}

		vars = append(vars, v)
	}

	return vars
}

func declSpecCount(decl *ast.GenDecl) int {
	count := 0
	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.ValueSpec:
			count += len(s.Names)
		case *ast.TypeSpec:
			count++
		case *ast.ImportSpec:
			count++
		}
	}
	return count
}

func valueSpecUsesIota(spec *ast.ValueSpec, previousUsesIota []bool) []bool {
	usesIota := make([]bool, len(spec.Names))
	if len(spec.Values) == 0 {
		copy(usesIota, previousUsesIota)
		return usesIota
	}

	for i := range spec.Names {
		if i < len(spec.Values) {
			usesIota[i] = exprUsesIota(spec.Values[i])
		}
	}
	return usesIota
}

func exprUsesIota(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if ok && ident.Name == "iota" {
			found = true
			return false
		}
		return true
	})
	return found
}
