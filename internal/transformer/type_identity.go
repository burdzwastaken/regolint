package transformer

import "go/ast"

func (t *Transformer) typeIdentity(expr ast.Expr) string {
	if expr == nil {
		return ""
	}

	if t.pkg != nil && t.pkg.TypesInfo != nil {
		if typ := t.pkg.TypesInfo.TypeOf(expr); typ != nil {
			return typ.String()
		}
	}

	return t.formatType(expr)
}
