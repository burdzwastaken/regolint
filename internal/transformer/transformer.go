package transformer

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/burdzwastaken/regolint/internal/model"
	"golang.org/x/tools/go/analysis"
)

// Transformer converts Go AST to CodeContext.
type Transformer struct {
	fset       *token.FileSet
	pkg        *analysis.Pass
	modulePath string
}

// New creates a new Transformer.
func New(pass *analysis.Pass, modulePath string) *Transformer {
	return &Transformer{
		fset:       pass.Fset,
		pkg:        pass,
		modulePath: modulePath,
	}
}

// Transform converts an AST file to CodeContext.
func (t *Transformer) Transform(file *ast.File, filePath string) *model.CodeContext {
	ctx := &model.CodeContext{
		FilePath:   filePath,
		ModulePath: t.modulePath,
		Package: model.PackageInfo{
			Name: file.Name.Name,
			Path: t.pkg.Pkg.Path(),
			Doc:  extractDoc(file.Doc),
		},
		Imports:     make([]model.ImportInfo, 0),
		Functions:   make([]model.FunctionInfo, 0),
		Types:       make([]model.TypeInfo, 0),
		Variables:   make([]model.VariableInfo, 0),
		Constants:   make([]model.VariableInfo, 0),
		Calls:       make([]model.CallInfo, 0),
		TypeUsages:  make([]model.TypeUsageInfo, 0),
		FieldAccess: make([]model.FieldAccessInfo, 0),
	}

	ctx.Imports = t.extractImports(file)

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			fn := t.extractFunction(node)
			ctx.Functions = append(ctx.Functions, fn)
			calls := t.extractCalls(node, fn.Name)
			ctx.Calls = append(ctx.Calls, calls...)
		case *ast.GenDecl:
			t.extractGenDecl(node, ctx)
		}
		return true
	})

	return ctx
}

func (t *Transformer) position(pos token.Pos) model.Position {
	p := t.fset.Position(pos)
	return model.Position{
		File:   filepath.Base(p.Filename),
		Line:   p.Line,
		Column: p.Column,
	}
}

func extractDoc(doc *ast.CommentGroup) string {
	if doc == nil {
		return ""
	}
	return strings.TrimSpace(doc.Text())
}

func isExported(name string) bool {
	if len(name) == 0 {
		return false
	}
	return name[0] >= 'A' && name[0] <= 'Z'
}

func isTestFunction(name string) bool {
	return strings.HasPrefix(name, "Test") ||
		strings.HasPrefix(name, "Benchmark") ||
		strings.HasPrefix(name, "Example") ||
		strings.HasPrefix(name, "Fuzz")
}
