package transformer

import (
	"go/ast"
	"go/types"

	"github.com/burdzwastaken/regolint/internal/model"
)

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

func (t *Transformer) typeRef(expr ast.Expr) *model.TypeRef {
	if expr == nil {
		return nil
	}

	display := t.formatType(expr)
	if t.pkg != nil && t.pkg.TypesInfo != nil {
		if typ := t.pkg.TypesInfo.TypeOf(expr); typ != nil {
			ref := t.typeRefFromType(typ)
			if ref != nil {
				ref.Display = display
			}
			return ref
		}
	}

	return t.typeRefFromSyntax(expr)
}

func (t *Transformer) typeRefFromType(typ types.Type) *model.TypeRef {
	if typ == nil {
		return nil
	}

	switch typ := typ.(type) {
	case *types.Basic:
		return basicTypeRef(typ)
	case *types.Named:
		return namedTypeRef(typ)
	case *types.Pointer:
		elem := t.typeRefFromType(typ.Elem())
		return elemTypeRef("pointer", "*", elem)
	case *types.Slice:
		elem := t.typeRefFromType(typ.Elem())
		return elemTypeRef("slice", "[]", elem)
	case *types.Array:
		elem := t.typeRefFromType(typ.Elem())
		return typedElemRef("array", typ, elem)
	case *types.Map:
		key := t.typeRefFromType(typ.Key())
		value := t.typeRefFromType(typ.Elem())
		return mapTypeRef(key, value)
	case *types.Chan:
		elem := t.typeRefFromType(typ.Elem())
		return typedElemRef("chan", typ, elem)
	case *types.Signature:
		return semanticTypeRef("func", typ)
	case *types.Interface:
		return semanticTypeRef("interface", typ)
	case *types.Struct:
		return semanticTypeRef("struct", typ)
	default:
		return semanticTypeRef("unknown", typ)
	}
}

func basicTypeRef(typ *types.Basic) *model.TypeRef {
	return &model.TypeRef{
		Kind:     "builtin",
		Display:  typ.Name(),
		Identity: typ.Name(),
		Source:   "semantic",
		Name:     typ.Name(),
	}
}

func namedTypeRef(typ *types.Named) *model.TypeRef {
	obj := typ.Obj()
	ref := &model.TypeRef{
		Kind:     "named",
		Display:  types.TypeString(typ, packageName),
		Identity: namedTypeIdentity(obj),
		Source:   "semantic",
		Name:     obj.Name(),
	}
	if pkg := obj.Pkg(); pkg != nil {
		ref.PackageName = pkg.Name()
		ref.PackagePath = pkg.Path()
	}
	return ref
}

func elemTypeRef(kind string, prefix string, elem *model.TypeRef) *model.TypeRef {
	return &model.TypeRef{
		Kind:     kind,
		Display:  prefix + typeRefDisplay(elem),
		Identity: prefix + typeRefIdentity(elem),
		Source:   "semantic",
		Elem:     elem,
	}
}

func typedElemRef(kind string, typ types.Type, elem *model.TypeRef) *model.TypeRef {
	ref := semanticTypeRef(kind, typ)
	ref.Elem = elem
	return ref
}

func mapTypeRef(key *model.TypeRef, value *model.TypeRef) *model.TypeRef {
	return &model.TypeRef{
		Kind:     "map",
		Display:  "map[" + typeRefDisplay(key) + "]" + typeRefDisplay(value),
		Identity: "map[" + typeRefIdentity(key) + "]" + typeRefIdentity(value),
		Source:   "semantic",
		Key:      key,
		Value:    value,
	}
}

func semanticTypeRef(kind string, typ types.Type) *model.TypeRef {
	return &model.TypeRef{
		Kind:     kind,
		Display:  types.TypeString(typ, packageName),
		Identity: types.TypeString(typ, packagePath),
		Source:   "semantic",
	}
}

func (t *Transformer) typeRefFromSyntax(expr ast.Expr) *model.TypeRef {
	switch expr := expr.(type) {
	case *ast.StarExpr:
		elem := t.typeRefFromSyntax(expr.X)
		return syntacticElemTypeRef("pointer", "*", elem)
	case *ast.ArrayType:
		elem := t.typeRefFromSyntax(expr.Elt)
		if expr.Len == nil {
			return syntacticElemTypeRef("slice", "[]", elem)
		}
		return t.syntacticTypeRef("array", expr, elem)
	case *ast.MapType:
		key := t.typeRefFromSyntax(expr.Key)
		value := t.typeRefFromSyntax(expr.Value)
		return t.syntacticMapTypeRef(expr, key, value)
	case *ast.ChanType:
		elem := t.typeRefFromSyntax(expr.Value)
		return t.syntacticTypeRef("chan", expr, elem)
	case *ast.Ident:
		kind := "named"
		if expr.Obj == nil {
			kind = "builtin"
		}
		return syntacticNamedTypeRef(kind, expr.Name)
	case *ast.SelectorExpr:
		return t.syntacticSelectorTypeRef(expr)
	case *ast.FuncType:
		return t.syntacticTypeRef("func", expr, nil)
	case *ast.InterfaceType:
		return t.syntacticTypeRef("interface", expr, nil)
	case *ast.StructType:
		return t.syntacticTypeRef("struct", expr, nil)
	default:
		return t.syntacticTypeRef("unknown", expr, nil)
	}
}

func syntacticElemTypeRef(kind string, prefix string, elem *model.TypeRef) *model.TypeRef {
	return &model.TypeRef{
		Kind:     kind,
		Display:  prefix + typeRefDisplay(elem),
		Identity: prefix + typeRefIdentity(elem),
		Source:   "syntactic",
		Elem:     elem,
	}
}

func (t *Transformer) syntacticTypeRef(kind string, expr ast.Expr, elem *model.TypeRef) *model.TypeRef {
	ref := &model.TypeRef{
		Kind:     kind,
		Display:  t.formatType(expr),
		Identity: t.formatType(expr),
		Source:   "syntactic",
	}
	if elem != nil {
		ref.Elem = elem
	}
	return ref
}

func (t *Transformer) syntacticMapTypeRef(expr ast.Expr, key *model.TypeRef, value *model.TypeRef) *model.TypeRef {
	ref := t.syntacticTypeRef("map", expr, nil)
	ref.Key = key
	ref.Value = value
	return ref
}

func syntacticNamedTypeRef(kind string, name string) *model.TypeRef {
	return &model.TypeRef{
		Kind:     kind,
		Display:  name,
		Identity: name,
		Source:   "syntactic",
		Name:     name,
	}
}

func (t *Transformer) syntacticSelectorTypeRef(expr *ast.SelectorExpr) *model.TypeRef {
	return &model.TypeRef{
		Kind:     "named",
		Display:  t.formatType(expr),
		Identity: t.formatType(expr),
		Source:   "syntactic",
		Name:     expr.Sel.Name,
	}
}

func namedTypeIdentity(obj *types.TypeName) string {
	if obj == nil {
		return ""
	}
	if pkg := obj.Pkg(); pkg != nil {
		return pkg.Path() + "." + obj.Name()
	}
	return obj.Name()
}

func packageName(pkg *types.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.Name()
}

func packagePath(pkg *types.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.Path()
}

func typeRefDisplay(ref *model.TypeRef) string {
	if ref == nil {
		return ""
	}
	if ref.Display != "" {
		return ref.Display
	}
	return ref.Identity
}

func typeRefIdentity(ref *model.TypeRef) string {
	if ref == nil {
		return ""
	}
	if ref.Identity != "" {
		return ref.Identity
	}
	return ref.Display
}
