package transformer

import "github.com/burdzwastaken/regolint/internal/model"

// BuildPackageContext aggregates multiple CodeContexts into a PackageContext.
// nolint:funlen
func BuildPackageContext(files []*model.CodeContext) *model.PackageContext {
	if len(files) == 0 {
		return nil
	}

	pkg := &model.PackageContext{
		ModulePath:           files[0].ModulePath,
		RuleOptions:          files[0].RuleOptions,
		Package:              files[0].Package,
		Files:                make([]model.CodeContext, 0, len(files)),
		AllImports:           make([]model.ImportInfo, 0),
		AllFunctions:         make([]model.FunctionInfo, 0),
		AllTypes:             make([]model.TypeInfo, 0),
		AllVariables:         make([]model.VariableInfo, 0),
		AllConstants:         make([]model.VariableInfo, 0),
		AllLines:             make([]model.LineInfo, 0),
		AllComments:          make([]model.CommentInfo, 0),
		AllLiterals:          make([]model.LiteralInfo, 0),
		AllCompositeLiterals: make([]model.CompositeLiteralInfo, 0),
		AllReturns:           make([]model.ReturnInfo, 0),
		AllIfs:               make([]model.IfInfo, 0),
		AllTypeAssertions:    make([]model.TypeAssertInfo, 0),
		AllMakeSlices:        make([]model.MakeSliceInfo, 0),
		AllAppends:           make([]model.AppendInfo, 0),
		AllResourceAcquires:  make([]model.ResourceInfo, 0),
		AllResourceCloses:    make([]model.ResourceClose, 0),
		AllResourceErrs:      make([]model.ResourceErr, 0),
		AllSubtests:          make([]model.SubtestInfo, 0),
		AllRangeLoops:        make([]model.RangeLoopInfo, 0),
		AllLoopVarCopies:     make([]model.LoopVarCopyInfo, 0),
		AllBlankAssignments:  make([]model.BlankAssignInfo, 0),
		AllDeclGroups:        make([]model.DeclGroupInfo, 0),
		AllDeclarations:      make([]model.DeclInfo, 0),
		AllCalls:             make([]model.CallInfo, 0),
		AllTypeUsages:        make([]model.TypeUsageInfo, 0),
		AllFieldAccesses:     make([]model.FieldAccessInfo, 0),
	}

	seen := make(map[string]bool)

	for _, f := range files {
		pkg.Files = append(pkg.Files, *f)

		for _, imp := range f.Imports {
			if !seen["import:"+imp.Path] {
				pkg.AllImports = append(pkg.AllImports, imp)
				seen["import:"+imp.Path] = true
			}
		}

		pkg.AllFunctions = append(pkg.AllFunctions, f.Functions...)
		pkg.AllTypes = append(pkg.AllTypes, f.Types...)
		pkg.AllVariables = append(pkg.AllVariables, f.Variables...)
		pkg.AllConstants = append(pkg.AllConstants, f.Constants...)
		pkg.AllLines = append(pkg.AllLines, f.Lines...)
		pkg.AllComments = append(pkg.AllComments, f.Comments...)
		pkg.AllLiterals = append(pkg.AllLiterals, f.Literals...)
		pkg.AllCompositeLiterals = append(pkg.AllCompositeLiterals, f.CompositeLiterals...)
		pkg.AllReturns = append(pkg.AllReturns, f.Returns...)
		pkg.AllIfs = append(pkg.AllIfs, f.Ifs...)
		pkg.AllTypeAssertions = append(pkg.AllTypeAssertions, f.TypeAssertions...)
		pkg.AllMakeSlices = append(pkg.AllMakeSlices, f.MakeSlices...)
		pkg.AllAppends = append(pkg.AllAppends, f.Appends...)
		pkg.AllResourceAcquires = append(pkg.AllResourceAcquires, f.ResourceAcquires...)
		pkg.AllResourceCloses = append(pkg.AllResourceCloses, f.ResourceCloses...)
		pkg.AllResourceErrs = append(pkg.AllResourceErrs, f.ResourceErrs...)
		pkg.AllSubtests = append(pkg.AllSubtests, f.Subtests...)
		pkg.AllRangeLoops = append(pkg.AllRangeLoops, f.RangeLoops...)
		pkg.AllLoopVarCopies = append(pkg.AllLoopVarCopies, f.LoopVarCopies...)
		pkg.AllBlankAssignments = append(pkg.AllBlankAssignments, f.BlankAssignments...)
		pkg.AllDeclGroups = append(pkg.AllDeclGroups, f.DeclGroups...)
		pkg.AllDeclarations = append(pkg.AllDeclarations, f.Declarations...)
		pkg.AllCalls = append(pkg.AllCalls, f.Calls...)
		pkg.AllTypeUsages = append(pkg.AllTypeUsages, f.TypeUsages...)
		pkg.AllFieldAccesses = append(pkg.AllFieldAccesses, f.FieldAccess...)
	}

	return pkg
}
