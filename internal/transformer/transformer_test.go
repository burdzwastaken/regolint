package transformer_test

import (
	"go/parser"
	"go/token"
	"testing"

	"github.com/burdzwastaken/regolint/internal/model"
	"github.com/burdzwastaken/regolint/internal/transformer"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

func TestTransformImports(t *testing.T) {
	src := `package example

import (
	"fmt"
	"os"
	alias "path/filepath"
)

func main() {
	fmt.Println("hello")
}
`
	ctx := transformSource(t, src)

	if len(ctx.Imports) != 3 {
		t.Fatalf("expected 3 imports, got %d", len(ctx.Imports))
	}

	tests := []struct {
		path  string
		alias string
	}{
		{"fmt", ""},
		{"os", ""},
		{"path/filepath", "alias"},
	}

	for i, tt := range tests {
		if ctx.Imports[i].Path != tt.path {
			t.Errorf("import %d: expected path %q, got %q", i, tt.path, ctx.Imports[i].Path)
		}
		if ctx.Imports[i].Alias != tt.alias {
			t.Errorf("import %d: expected alias %q, got %q", i, tt.alias, ctx.Imports[i].Alias)
		}
	}
}

func TestTransformFunctions(t *testing.T) {
	src := `package example

// TestFunc is a test function
func TestFunc() {}

func privateFunc(a, b int) (string, error) {
	return "", nil
}

func (s *Service) Method(ctx context.Context) error {
	return nil
}
`
	ctx := transformSource(t, src)

	if len(ctx.Functions) != 3 {
		t.Fatalf("expected 3 functions, got %d", len(ctx.Functions))
	}

	tests := []struct {
		name       string
		isExported bool
		isTest     bool
		receiver   string
		paramCount int
		retCount   int
	}{
		{"TestFunc", true, true, "", 0, 0},
		{"privateFunc", false, false, "", 2, 2},
		{"Method", true, false, "*Service", 1, 1},
	}

	for i, tt := range tests {
		fn := ctx.Functions[i]
		if fn.Name != tt.name {
			t.Errorf("function %d: expected name %q, got %q", i, tt.name, fn.Name)
		}
		if fn.IsExported != tt.isExported {
			t.Errorf("function %s: expected exported=%v, got %v", fn.Name, tt.isExported, fn.IsExported)
		}
		if fn.IsTest != tt.isTest {
			t.Errorf("function %s: expected isTest=%v, got %v", fn.Name, tt.isTest, fn.IsTest)
		}
		if fn.Receiver != tt.receiver {
			t.Errorf("function %s: expected receiver %q, got %q", fn.Name, tt.receiver, fn.Receiver)
		}
		if len(fn.Parameters) != tt.paramCount {
			t.Errorf("function %s: expected %d params, got %d", fn.Name, tt.paramCount, len(fn.Parameters))
		}
		if len(fn.Returns) != tt.retCount {
			t.Errorf("function %s: expected %d returns, got %d", fn.Name, tt.retCount, len(fn.Returns))
		}
	}
}

func TestTransformTypes(t *testing.T) {
	src := `package example

type UserService struct {
	logger Logger
	Name   string ` + "`json:\"name\"`" + `
}

type Repository interface {
	Get(id string) (User, error)
	Create(user User) error
}

type ID = string
`
	ctx := transformSource(t, src)

	if len(ctx.Types) != 3 {
		t.Fatalf("expected 3 types, got %d", len(ctx.Types))
	}

	tests := []struct {
		name       string
		kind       string
		isExported bool
		fieldCount int
	}{
		{"UserService", "struct", true, 2},
		{"Repository", "interface", true, 0},
		{"ID", "alias", true, 0},
	}

	for i, tt := range tests {
		typ := ctx.Types[i]
		if typ.Name != tt.name {
			t.Errorf("type %d: expected name %q, got %q", i, tt.name, typ.Name)
		}
		if typ.Kind != tt.kind {
			t.Errorf("type %s: expected kind %q, got %q", typ.Name, tt.kind, typ.Kind)
		}
		if typ.IsExported != tt.isExported {
			t.Errorf("type %s: expected exported=%v, got %v", typ.Name, tt.isExported, typ.IsExported)
		}
	}

	userService := ctx.Types[0]
	if len(userService.Fields) != 2 {
		t.Fatalf("UserService: expected 2 fields, got %d", len(userService.Fields))
	}
	if userService.Fields[1].Tags != `json:"name"` {
		t.Errorf("UserService.Name: expected json tag, got %q", userService.Fields[1].Tags)
	}

	repo := ctx.Types[1]
	if len(repo.Methods) != 2 {
		t.Fatalf("Repository: expected 2 methods, got %d", len(repo.Methods))
	}
}

func TestTransformCalls(t *testing.T) {
	src := `package example

import "fmt"

func main() {
	fmt.Println("hello")
	helper()
	s := &Service{}
	s.Method()
}

func helper() {}
`
	ctx := transformSource(t, src)

	var mainCalls int
	for _, call := range ctx.Calls {
		if call.InFunction == "main" {
			mainCalls++
		}
	}

	if mainCalls < 3 {
		t.Errorf("expected at least 3 calls in main, got %d", mainCalls)
	}

	var hasFmtPrintln bool
	for _, call := range ctx.Calls {
		if call.Function == "Println" && call.Package == "fmt" {
			hasFmtPrintln = true
			break
		}
	}
	if !hasFmtPrintln {
		t.Error("expected to find fmt.Println call")
	}
}

func TestTransformConstants(t *testing.T) {
	src := `package example

const (
	MaxRetries = 3
	apiKey     = "secret"
)

var globalVar = "value"
`
	ctx := transformSource(t, src)

	if len(ctx.Constants) != 2 {
		t.Fatalf("expected 2 constants, got %d", len(ctx.Constants))
	}

	if ctx.Constants[0].Name != "MaxRetries" || !ctx.Constants[0].IsExported {
		t.Error("MaxRetries should be exported constant")
	}
	if ctx.Constants[1].Name != "apiKey" || ctx.Constants[1].IsExported {
		t.Error("apiKey should be unexported constant")
	}

	if len(ctx.Variables) != 1 {
		t.Fatalf("expected 1 variable, got %d", len(ctx.Variables))
	}
	if ctx.Variables[0].Name != "globalVar" {
		t.Error("expected globalVar variable")
	}
}

func TestComplexity(t *testing.T) {
	src := `package example

func simple() {}

func complex(x int) {
	if x > 0 {
		for i := 0; i < x; i++ {
			if i%2 == 0 {
				continue
			}
		}
	} else if x < 0 {
		switch x {
		case -1:
			return
		case -2:
			return
		}
	}
}
`
	ctx := transformSource(t, src)

	if len(ctx.Functions) != 2 {
		t.Fatalf("expected 2 functions, got %d", len(ctx.Functions))
	}

	simple := ctx.Functions[0]
	complex := ctx.Functions[1]

	if simple.Complexity != 1 {
		t.Errorf("simple: expected complexity 1, got %d", simple.Complexity)
	}

	if complex.Complexity < 5 {
		t.Errorf("complex: expected complexity >= 5, got %d", complex.Complexity)
	}
}

func transformSource(t *testing.T, src string) *model.CodeContext {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing source: %v", err)
	}

	cfg := &packages.Config{
		Mode: packages.NeedTypes | packages.NeedName,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "std")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("loading packages: %v", err)
	}

	pass := &analysis.Pass{
		Fset: fset,
		Pkg:  pkgs[0].Types,
	}

	trans := transformer.New(pass, "github.com/test/example")
	return trans.Transform(file, "test.go")
}
