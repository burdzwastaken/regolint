package transformer

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/burdzwastaken/regolint/internal/model"
	"github.com/burdzwastaken/regolint/internal/nolint"
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
// nolint:funlen
func (t *Transformer) Transform(file *ast.File, filePath string) *model.CodeContext {
	ctx := &model.CodeContext{
		FilePath:   filePath,
		ModulePath: t.modulePath,
		Package: model.PackageInfo{
			Name: file.Name.Name,
			Path: t.pkg.Pkg.Path(),
			Doc:  extractDoc(file.Doc),
		},
		Imports:           make([]model.ImportInfo, 0),
		Functions:         make([]model.FunctionInfo, 0),
		Types:             make([]model.TypeInfo, 0),
		Variables:         make([]model.VariableInfo, 0),
		Constants:         make([]model.VariableInfo, 0),
		Lines:             make([]model.LineInfo, 0),
		Comments:          make([]model.CommentInfo, 0),
		Literals:          make([]model.LiteralInfo, 0),
		CompositeLiterals: make([]model.CompositeLiteralInfo, 0),
		Returns:           make([]model.ReturnInfo, 0),
		Ifs:               make([]model.IfInfo, 0),
		TypeAssertions:    make([]model.TypeAssertInfo, 0),
		MakeSlices:        make([]model.MakeSliceInfo, 0),
		Appends:           make([]model.AppendInfo, 0),
		ResourceAcquires:  make([]model.ResourceInfo, 0),
		ResourceCloses:    make([]model.ResourceClose, 0),
		ResourceErrs:      make([]model.ResourceErr, 0),
		Subtests:          make([]model.SubtestInfo, 0),
		RangeLoops:        make([]model.RangeLoopInfo, 0),
		LoopVarCopies:     make([]model.LoopVarCopyInfo, 0),
		BlankAssignments:  make([]model.BlankAssignInfo, 0),
		DeclGroups:        make([]model.DeclGroupInfo, 0),
		Declarations:      make([]model.DeclInfo, 0),
		Calls:             make([]model.CallInfo, 0),
		TypeUsages:        make([]model.TypeUsageInfo, 0),
		FieldAccess:       make([]model.FieldAccessInfo, 0),
	}

	ctx.Imports = t.extractImports(file)
	ctx.Lines = t.extractLines(filePath, file)
	ctx.Comments = t.extractCommentGroups(file)
	ctx.Nolints = t.extractNolints(file)
	ctx.CompositeLiterals = append(ctx.CompositeLiterals, t.extractPackageCompositeLiterals(file)...)

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			fn := t.extractFunction(node)
			ctx.Functions = append(ctx.Functions, fn)
			ctx.Declarations = append(ctx.Declarations, model.DeclInfo{
				Kind:     "func",
				Name:     node.Name.Name,
				Position: t.position(node.Pos()),
			})
			ctx.Literals = append(ctx.Literals, t.extractLiterals(node.Body, fn.Name)...)
			ctx.CompositeLiterals = append(ctx.CompositeLiterals, t.extractFunctionCompositeLiterals(node.Body, fn.Name)...)
			ctx.Returns = append(ctx.Returns, t.extractReturns(node.Body, fn.Name, fn.Receiver)...)
			ctx.Ifs = append(ctx.Ifs, t.extractIfs(node.Body, fn.Name, fn.Receiver)...)
			ctx.TypeAssertions = append(ctx.TypeAssertions, t.extractTypeAssertions(node.Body, fn.Name)...)
			makeSlices, appends := t.extractMakeAppendFacts(node.Body, fn.Name)
			ctx.MakeSlices = append(ctx.MakeSlices, makeSlices...)
			ctx.Appends = append(ctx.Appends, appends...)
			resources, closes, errs := t.extractResourceFacts(node.Body, fn.Name)
			ctx.ResourceAcquires = append(ctx.ResourceAcquires, resources...)
			ctx.ResourceCloses = append(ctx.ResourceCloses, closes...)
			ctx.ResourceErrs = append(ctx.ResourceErrs, errs...)
			ctx.Subtests = append(ctx.Subtests, t.extractSubtests(node.Body, fn.Name)...)
			rangeLoops, loopVarCopies := t.extractRangeLoopFacts(node.Body, fn.Name)
			ctx.RangeLoops = append(ctx.RangeLoops, rangeLoops...)
			ctx.LoopVarCopies = append(ctx.LoopVarCopies, loopVarCopies...)
			ctx.BlankAssignments = append(ctx.BlankAssignments, t.extractBlankAssignments(node.Body, fn.Name)...)
			calls := t.extractCalls(node, fn.Name)
			ctx.Calls = append(ctx.Calls, calls...)
			return false
		case *ast.GenDecl:
			t.extractGenDecl(node, ctx)
		}
		return true
	})

	return ctx
}

func (t *Transformer) extractCommentGroups(file *ast.File) []model.CommentInfo {
	comments := make([]model.CommentInfo, 0, len(file.Comments))
	for _, group := range file.Comments {
		for _, comment := range group.List {
			for idx, text := range cleanComment(comment.Text) {
				comments = append(comments, model.CommentInfo{
					Text:        text,
					Raw:         comment.Text,
					IsFirstLine: idx == 0,
					Position:    t.position(comment.Pos()),
				})
			}
		}
	}
	return comments
}

func cleanComment(text string) []string {
	text = strings.TrimPrefix(text, "//")
	text = strings.TrimPrefix(text, "/*")
	text = strings.TrimSuffix(text, "*/")

	lines := strings.Split(text, "\n")
	comments := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "*"))
		if line != "" {
			comments = append(comments, line)
		}
	}
	return comments
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

func (t *Transformer) extractNolints(file *ast.File) []model.NolintDirective {
	directives := nolint.Extract(t.fset, file)
	result := make([]model.NolintDirective, len(directives))
	for i, d := range directives {
		result[i] = model.NolintDirective{
			Line:    d.Line,
			EndLine: d.EndLine,
			Rules:   d.Rules,
			Reason:  d.Reason,
		}
	}
	return result
}
