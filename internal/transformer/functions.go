package transformer

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractFunction(fn *ast.FuncDecl) model.FunctionInfo {
	info := model.FunctionInfo{
		Name:       fn.Name.Name,
		IsExported: isExported(fn.Name.Name),
		IsTest:     isTestFunction(fn.Name.Name),
		Position:   t.position(fn.Pos()),
		Parameters: make([]model.ParameterInfo, 0),
		Returns:    make([]model.ParameterInfo, 0),
	}

	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		info.Receiver = t.formatReceiver(fn.Recv.List[0])
	}

	if fn.Type.Params != nil {
		info.Parameters = t.extractParams(fn.Type.Params)
	}

	if fn.Type.Results != nil {
		info.Returns = t.extractParams(fn.Type.Results)
	}

	if fn.Body != nil {
		startLine := t.fset.Position(fn.Body.Lbrace).Line
		endLine := t.fset.Position(fn.Body.Rbrace).Line
		info.LineCount = endLine - startLine + 1
		info.Complexity = t.calculateComplexity(fn.Body)
	}

	if fn.Doc != nil {
		info.Comments = extractComments(fn.Doc)
	}

	info.Annotations = extractAnnotations(info.Comments)

	return info
}

func (t *Transformer) extractParams(fields *ast.FieldList) []model.ParameterInfo {
	params := make([]model.ParameterInfo, 0)

	for _, field := range fields.List {
		typeStr := t.formatType(field.Type)

		if len(field.Names) == 0 {
			params = append(params, model.ParameterInfo{Type: typeStr})
		} else {
			for _, name := range field.Names {
				params = append(params, model.ParameterInfo{
					Name: name.Name,
					Type: typeStr,
				})
			}
		}
	}

	return params
}

func (t *Transformer) formatReceiver(field *ast.Field) string {
	return t.formatType(field.Type)
}

func (t *Transformer) formatType(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return "*" + t.formatType(e.X)
	case *ast.SelectorExpr:
		return t.formatType(e.X) + "." + e.Sel.Name
	case *ast.ArrayType:
		if e.Len == nil {
			return "[]" + t.formatType(e.Elt)
		}
		return "[...]" + t.formatType(e.Elt)
	case *ast.MapType:
		return "map[" + t.formatType(e.Key) + "]" + t.formatType(e.Value)
	case *ast.ChanType:
		switch e.Dir {
		case ast.SEND:
			return "chan<- " + t.formatType(e.Value)
		case ast.RECV:
			return "<-chan " + t.formatType(e.Value)
		default:
			return "chan " + t.formatType(e.Value)
		}
	case *ast.FuncType:
		return "func(...)"
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.StructType:
		return "struct{}"
	case *ast.Ellipsis:
		return "..." + t.formatType(e.Elt)
	default:
		return "unknown"
	}
}

func (t *Transformer) calculateComplexity(body *ast.BlockStmt) int {
	complexity := 1

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			complexity++
		case *ast.ForStmt, *ast.RangeStmt:
			complexity++
		case *ast.SwitchStmt, *ast.TypeSwitchStmt:
			complexity++
		case *ast.CaseClause:
			complexity++
		case *ast.SelectStmt:
			complexity++
		case *ast.CommClause:
			complexity++
		case *ast.BinaryExpr:
			if node.Op == token.LAND || node.Op == token.LOR {
				complexity++
			}
		}
		return true
	})

	return complexity
}

func extractComments(doc *ast.CommentGroup) []string {
	if doc == nil {
		return nil
	}

	comments := make([]string, 0, len(doc.List))
	for _, c := range doc.List {
		text := strings.TrimPrefix(c.Text, "//")
		text = strings.TrimPrefix(text, "/*")
		text = strings.TrimSuffix(text, "*/")
		text = strings.TrimSpace(text)
		if text != "" {
			comments = append(comments, text)
		}
	}
	return comments
}

func extractAnnotations(comments []string) map[string]any {
	annotations := make(map[string]any)

	for _, comment := range comments {
		if strings.HasPrefix(comment, "@") {
			parts := strings.SplitN(comment, " ", 2)
			key := strings.TrimPrefix(parts[0], "@")
			if len(parts) > 1 {
				annotations[key] = strings.TrimSpace(parts[1])
			} else {
				annotations[key] = true
			}
		}
	}

	if len(annotations) == 0 {
		return nil
	}
	return annotations
}
