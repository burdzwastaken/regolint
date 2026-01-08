package transformer

import (
	"go/ast"
	"strings"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractImports(file *ast.File) []model.ImportInfo {
	imports := make([]model.ImportInfo, 0, len(file.Imports))

	for _, imp := range file.Imports {
		info := model.ImportInfo{
			Path:     strings.Trim(imp.Path.Value, `"`),
			Position: t.position(imp.Pos()),
		}

		if imp.Name != nil {
			info.Alias = imp.Name.Name
		}

		imports = append(imports, info)
	}

	return imports
}
