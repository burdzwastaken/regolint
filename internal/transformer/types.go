package transformer

import (
	"go/ast"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractType(spec *ast.TypeSpec, doc *ast.CommentGroup) model.TypeInfo {
	info := model.TypeInfo{
		Name:       spec.Name.Name,
		IsExported: isExported(spec.Name.Name),
		Position:   t.position(spec.Pos()),
		Doc:        extractDoc(doc),
		Fields:     make([]model.FieldInfo, 0),
		Methods:    make([]model.MethodInfo, 0),
		Embeds:     make([]string, 0),
	}

	switch typeExpr := spec.Type.(type) {
	case *ast.StructType:
		info.Kind = "struct"
		info.Fields, info.Embeds = t.extractStructFields(typeExpr)
	case *ast.InterfaceType:
		info.Kind = "interface"
		info.Methods, info.Embeds = t.extractInterfaceMethods(typeExpr)
	case *ast.FuncType:
		info.Kind = "func"
	default:
		info.Kind = "alias"
	}

	return info
}

func (t *Transformer) extractStructFields(st *ast.StructType) ([]model.FieldInfo, []string) {
	if st.Fields == nil {
		return nil, nil
	}

	fields := make([]model.FieldInfo, 0)
	embeds := make([]string, 0)

	for _, field := range st.Fields.List {
		typeStr := t.formatType(field.Type)

		if len(field.Names) == 0 {
			embeds = append(embeds, typeStr)
			fields = append(fields, model.FieldInfo{
				Name:       typeStr,
				Type:       typeStr,
				IsEmbedded: true,
				Position:   t.position(field.Pos()),
				Tags:       extractTags(field.Tag),
			})
			continue
		}

		for _, name := range field.Names {
			fields = append(fields, model.FieldInfo{
				Name:       name.Name,
				Type:       typeStr,
				IsExported: isExported(name.Name),
				Position:   t.position(name.Pos()),
				Tags:       extractTags(field.Tag),
			})
		}
	}

	return fields, embeds
}

func (t *Transformer) extractInterfaceMethods(iface *ast.InterfaceType) ([]model.MethodInfo, []string) {
	if iface.Methods == nil {
		return nil, nil
	}

	methods := make([]model.MethodInfo, 0)
	embeds := make([]string, 0)

	for _, field := range iface.Methods.List {
		if len(field.Names) == 0 {
			embeds = append(embeds, t.formatType(field.Type))
			continue
		}

		if fn, ok := field.Type.(*ast.FuncType); ok {
			for _, name := range field.Names {
				method := model.MethodInfo{
					Name:       name.Name,
					IsExported: isExported(name.Name),
					Parameters: make([]model.ParameterInfo, 0),
					Returns:    make([]model.ParameterInfo, 0),
				}

				if fn.Params != nil {
					method.Parameters = t.extractParams(fn.Params)
				}
				if fn.Results != nil {
					method.Returns = t.extractParams(fn.Results)
				}

				methods = append(methods, method)
			}
		}
	}

	return methods, embeds
}

func extractTags(tag *ast.BasicLit) string {
	if tag == nil {
		return ""
	}
	s := tag.Value
	if len(s) >= 2 && s[0] == '`' && s[len(s)-1] == '`' {
		return s[1 : len(s)-1]
	}
	return s
}
