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
		info.MaxIfDepth = maxIfDepth(fn.Body)
		info.HasNakedRet = hasNakedReturn(fn.Body)
	}

	if fn.Doc != nil {
		info.Comments = extractComments(fn.Doc)
	}

	info.Annotations = extractAnnotations(info.Comments)

	return info
}

func hasNakedReturn(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		found = len(ret.Results) == 0
		return !found
	})
	return found
}

func (t *Transformer) extractReturns(body *ast.BlockStmt, funcName string, receiver string) []model.ReturnInfo {
	if body == nil {
		return nil
	}

	returns := make([]model.ReturnInfo, 0, len(body.List))
	ast.Inspect(body, func(n ast.Node) bool {
		switch current := n.(type) {
		case nil:
			return true
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			info := model.ReturnInfo{
				Function: funcName,
				Receiver: receiver,
				Results:  make([]string, 0, len(current.Results)),
				IsNaked:  len(current.Results) == 0,
				Position: t.position(current.Pos()),
			}
			for _, result := range current.Results {
				info.Results = append(info.Results, t.formatExpr(result))
			}
			returns = append(returns, info)
		}
		return true
	})

	return returns
}

func (t *Transformer) extractIfs(body *ast.BlockStmt, funcName string, receiver string) []model.IfInfo {
	if body == nil {
		return nil
	}

	ifs := make([]model.IfInfo, 0)
	ast.Inspect(body, func(n ast.Node) bool {
		switch current := n.(type) {
		case nil:
			return true
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			errorVar, isErrNotNil := errNotNilVar(current.Cond)
			info := model.IfInfo{
				Function:    funcName,
				Receiver:    receiver,
				Condition:   t.formatExpr(current.Cond),
				ErrorVar:    errorVar,
				IsErrNotNil: isErrNotNil,
				Returns:     t.directReturns(current.Body, funcName, receiver),
				Position:    t.position(current.Pos()),
			}
			ifs = append(ifs, info)
		}
		return true
	})

	return ifs
}

func (t *Transformer) directReturns(body *ast.BlockStmt, funcName string, receiver string) []model.ReturnInfo {
	if body == nil {
		return nil
	}

	returns := make([]model.ReturnInfo, 0, len(body.List))
	for _, stmt := range body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok {
			continue
		}

		info := model.ReturnInfo{
			Function: funcName,
			Receiver: receiver,
			Results:  make([]string, 0, len(ret.Results)),
			IsNaked:  len(ret.Results) == 0,
			Position: t.position(ret.Pos()),
		}
		for _, result := range ret.Results {
			info.Results = append(info.Results, t.formatExpr(result))
		}
		returns = append(returns, info)
	}

	return returns
}

func errNotNilVar(expr ast.Expr) (string, bool) {
	switch current := expr.(type) {
	case *ast.ParenExpr:
		return errNotNilVar(current.X)
	case *ast.BinaryExpr:
		if current.Op == token.NEQ {
			if name, ok := identComparedToNil(current.X, current.Y); ok {
				return name, errorLikeName(name)
			}
			if name, ok := identComparedToNil(current.Y, current.X); ok {
				return name, errorLikeName(name)
			}
		}
		if current.Op == token.LAND {
			if name, ok := errNotNilVar(current.X); ok {
				return name, true
			}
			return errNotNilVar(current.Y)
		}
	}

	return "", false
}

func identComparedToNil(left ast.Expr, right ast.Expr) (string, bool) {
	ident, ok := left.(*ast.Ident)
	if !ok || ident.Name == "nil" {
		return "", false
	}

	rightIdent, ok := right.(*ast.Ident)
	if !ok || rightIdent.Name != "nil" {
		return "", false
	}

	return ident.Name, true
}

func errorLikeName(name string) bool {
	lowerName := strings.ToLower(name)
	return lowerName == "err" ||
		lowerName == "error" ||
		strings.HasPrefix(lowerName, "err") ||
		strings.HasSuffix(lowerName, "err")
}

func maxIfDepth(body *ast.BlockStmt) int {
	var walk func(ast.Node, int) int
	walk = func(node ast.Node, depth int) int {
		maxDepth := depth
		ast.Inspect(node, func(n ast.Node) bool {
			switch current := n.(type) {
			case nil:
				return true
			case *ast.FuncLit:
				return false
			case *ast.IfStmt:
				currentDepth := depth + 1
				maxDepth = max(maxDepth, currentDepth)
				maxDepth = max(maxDepth, walk(current.Body, currentDepth))
				if current.Else != nil {
					maxDepth = max(maxDepth, walk(current.Else, currentDepth))
				}
				return false
			}
			return true
		})
		return maxDepth
	}

	return walk(body, 0)
}

func (t *Transformer) extractParams(fields *ast.FieldList) []model.ParameterInfo {
	params := make([]model.ParameterInfo, 0, len(fields.List))

	for _, field := range fields.List {
		typeStr := t.formatType(field.Type)
		typeIdentity := t.typeIdentity(field.Type)
		typeRef := t.typeRef(field.Type)
		_, isVariadic := field.Type.(*ast.Ellipsis)

		if len(field.Names) == 0 {
			params = append(params, model.ParameterInfo{
				Type:         typeStr,
				TypeIdentity: typeIdentity,
				TypeRef:      typeRef,
				IsVariadic:   isVariadic,
			})
		} else {
			for _, name := range field.Names {
				params = append(params, model.ParameterInfo{
					Name:         name.Name,
					Type:         typeStr,
					TypeIdentity: typeIdentity,
					TypeRef:      typeRef,
					IsVariadic:   isVariadic,
				})
			}
		}
	}

	return params
}

func (t *Transformer) formatReceiver(field *ast.Field) string {
	return t.formatType(field.Type)
}

// nolint:gocyclo
func (t *Transformer) formatType(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return "*" + t.formatType(e.X)
	case *ast.SelectorExpr:
		return t.formatType(e.X) + "." + e.Sel.Name
	case *ast.IndexExpr:
		return t.formatType(e.X) + "[...]"
	case *ast.IndexListExpr:
		return t.formatType(e.X) + "[...]"
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
