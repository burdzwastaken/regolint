package transformer

import "github.com/burdzwastaken/regolint/internal/model"

// BuildPackageContext aggregates multiple CodeContexts into a PackageContext.
func BuildPackageContext(files []*model.CodeContext) *model.PackageContext {
	if len(files) == 0 {
		return nil
	}

	pkg := &model.PackageContext{
		ModulePath:   files[0].ModulePath,
		Package:      files[0].Package,
		Files:        make([]model.CodeContext, 0, len(files)),
		AllImports:   make([]model.ImportInfo, 0),
		AllFunctions: make([]model.FunctionInfo, 0),
		AllTypes:     make([]model.TypeInfo, 0),
		AllVariables: make([]model.VariableInfo, 0),
		AllConstants: make([]model.VariableInfo, 0),
		AllCalls:     make([]model.CallInfo, 0),
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
		pkg.AllCalls = append(pkg.AllCalls, f.Calls...)
	}

	return pkg
}
