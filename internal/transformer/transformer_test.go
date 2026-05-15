package transformer_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
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

func variadic(format string, args ...any) {}

func (s *Service) Method(ctx context.Context) error {
	return nil
}
`
	ctx := transformSource(t, src)

	if len(ctx.Functions) != 4 {
		t.Fatalf("expected 4 functions, got %d", len(ctx.Functions))
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
		{"variadic", false, false, "", 2, 0},
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

	variadic := ctx.Functions[2]
	lastParam := variadic.Parameters[1]
	if !lastParam.IsVariadic {
		t.Fatalf("expected args parameter to be variadic")
	}
	if lastParam.Type != "...any" {
		t.Fatalf("expected args parameter type ...any, got %q", lastParam.Type)
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
	Logf(format string, args ...any)
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
	if len(repo.Methods) != 3 {
		t.Fatalf("Repository: expected 3 methods, got %d", len(repo.Methods))
	}
	logf := repo.Methods[2]
	lastParam := logf.Parameters[1]
	if !lastParam.IsVariadic {
		t.Fatalf("Repository.Logf: expected args parameter to be variadic")
	}
	if lastParam.Type != "...any" {
		t.Fatalf("Repository.Logf: expected args parameter type ...any, got %q", lastParam.Type)
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
	func() {
		fmt.Println("nested")
	}()
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
	var hasNestedFmtPrintln bool
	for _, call := range ctx.Calls {
		if call.Function == "Println" && call.Package == "fmt" && !call.InFuncLit {
			hasFmtPrintln = true
		}
		if call.Function == "Println" && call.Package == "fmt" && call.InFuncLit {
			hasNestedFmtPrintln = true
		}
	}
	if !hasFmtPrintln {
		t.Error("expected to find fmt.Println call")
	}
	if !hasNestedFmtPrintln {
		t.Error("expected to find nested fmt.Println call")
	}
}

func TestTransformCallArgsPreserveConversions(t *testing.T) {
	src := `package example

import (
	"bytes"
	"strings"
)

func main(data []byte, text string) {
	strings.Contains(string(data), "needle")
	bytes.Contains([]byte(text), []byte("needle"))
}
`
	ctx := transformSource(t, src)

	var foundStringConversion bool
	var foundBytesConversion bool

	for _, call := range ctx.Calls {
		if call.Package == "strings" && call.Function == "Contains" && len(call.Args) > 0 && call.Args[0] == "string(...)" {
			foundStringConversion = true
		}
		if call.Package == "bytes" && call.Function == "Contains" && len(call.Args) > 0 && call.Args[0] == "[]byte(...)" {
			foundBytesConversion = true
		}
	}

	if !foundStringConversion {
		t.Error("expected strings.Contains argument to preserve string conversion")
	}
	if !foundBytesConversion {
		t.Error("expected bytes.Contains argument to preserve []byte conversion")
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

func TestTransformDeclGroupsAndIota(t *testing.T) {
	src := `package example

const (
	First = iota
	Second
	Explicit = 10
	A, B = iota, 10
	C, D
)

var one, two = 1, 2

type User struct{}
`
	ctx := transformSource(t, src)

	if len(ctx.DeclGroups) != 3 {
		t.Fatalf("expected 3 declaration groups, got %d", len(ctx.DeclGroups))
	}
	if ctx.DeclGroups[0].Kind != "const" || !ctx.DeclGroups[0].IsGrouped || ctx.DeclGroups[0].Count != 7 {
		t.Fatalf("unexpected const declaration group: %#v", ctx.DeclGroups[0])
	}
	if ctx.DeclGroups[1].Kind != "var" || ctx.DeclGroups[1].IsGrouped || ctx.DeclGroups[1].Count != 2 {
		t.Fatalf("unexpected var declaration group: %#v", ctx.DeclGroups[1])
	}
	if len(ctx.Declarations) != 10 {
		t.Fatalf("expected 10 declarations, got %d", len(ctx.Declarations))
	}
	if ctx.Declarations[0].Kind != "const" || ctx.Declarations[0].Name != "First" {
		t.Fatalf("unexpected first declaration: %#v", ctx.Declarations[0])
	}
	if ctx.Declarations[9].Kind != "type" || ctx.Declarations[9].Name != "User" {
		t.Fatalf("unexpected final declaration: %#v", ctx.Declarations[9])
	}

	if len(ctx.Constants) != 7 {
		t.Fatalf("expected 7 constants, got %d", len(ctx.Constants))
	}
	constantsByName := make(map[string]bool, len(ctx.Constants))
	for _, constant := range ctx.Constants {
		constantsByName[constant.Name] = constant.UsesIota
	}
	for _, name := range []string{"First", "Second", "A", "C"} {
		if !constantsByName[name] {
			t.Fatalf("expected %s to use iota: %#v", name, ctx.Constants)
		}
	}
	for _, name := range []string{"Explicit", "B", "D"} {
		if constantsByName[name] {
			t.Fatalf("expected %s not to use iota: %#v", name, ctx.Constants)
		}
	}
	if ctx.Constants[0].BlockID != ctx.Constants[6].BlockID {
		t.Fatalf("expected constants in the same block: %#v", ctx.Constants)
	}
}

func TestTransformMaxIfDepth(t *testing.T) {
	src := `package example

func nested(a, b, c bool) {
	if a {
		if b {
			if c {
				return
			}
		}
	}
}

func ignoresFunctionLiteral(a bool) {
	fn := func() {
		if a {
			if a {
				return
			}
		}
	}
	fn()
}
`
	ctx := transformSource(t, src)

	if len(ctx.Functions) != 2 {
		t.Fatalf("expected 2 functions, got %d", len(ctx.Functions))
	}
	if ctx.Functions[0].MaxIfDepth != 3 {
		t.Fatalf("nested: expected max if depth 3, got %d", ctx.Functions[0].MaxIfDepth)
	}
	if ctx.Functions[1].MaxIfDepth != 0 {
		t.Fatalf("ignoresFunctionLiteral: expected max if depth 0, got %d", ctx.Functions[1].MaxIfDepth)
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

func TestNakedReturnDetectionIgnoresFunctionLiterals(t *testing.T) {
	src := `package example

func outer() (err error) {
	fn := func() {
		return
	}
	fn()
	return nil
}

func naked() (err error) {
	return
}
`
	ctx := transformSource(t, src)

	if ctx.Functions[0].HasNakedRet {
		t.Error("outer should not be marked as naked return because only nested function literal has a bare return")
	}
	if !ctx.Functions[1].HasNakedRet {
		t.Error("naked should be marked as naked return")
	}
}

func TestTransformReturnsIgnoresFunctionLiterals(t *testing.T) {
	src := `package example

func outer() (*User, error) {
	fn := func() {
		return
	}
	fn()
	return nil, nil
}

func explicit() (*User, error) {
	return user, err
}
`
	ctx := transformSource(t, src)

	if len(ctx.Returns) != 2 {
		t.Fatalf("expected 2 return statements, got %d", len(ctx.Returns))
	}

	first := ctx.Returns[0]
	if first.Function != "outer" {
		t.Fatalf("expected first return from outer, got %q", first.Function)
	}
	if first.IsNaked {
		t.Fatal("outer return should not be naked")
	}
	if got, want := strings.Join(first.Results, ","), "nil,nil"; got != want {
		t.Fatalf("expected first return results %q, got %q", want, got)
	}

	second := ctx.Returns[1]
	if got, want := strings.Join(second.Results, ","), "user,err"; got != want {
		t.Fatalf("expected second return results %q, got %q", want, got)
	}
}

func TestTransformReturnsIncludeReceivers(t *testing.T) {
	src := `package example

func (a *A) Read() (*Item, error) {
	return nil, nil
}

func (b B) Read() (int, error) {
	return 0, nil
}

func (c Cache[string]) Read() (*Item, error) {
	return nil, nil
}
`
	ctx := transformSource(t, src)

	if len(ctx.Returns) != 3 {
		t.Fatalf("expected 3 return statements, got %d", len(ctx.Returns))
	}
	if ctx.Returns[0].Receiver != "*A" {
		t.Fatalf("expected first return receiver *A, got %q", ctx.Returns[0].Receiver)
	}
	if ctx.Returns[1].Receiver != "B" {
		t.Fatalf("expected second return receiver B, got %q", ctx.Returns[1].Receiver)
	}
	if ctx.Returns[2].Receiver != "Cache[...]" {
		t.Fatalf("expected third return receiver Cache[...], got %q", ctx.Returns[2].Receiver)
	}
}

func TestTransformIfsCaptureErrNotNilReturns(t *testing.T) {
	src := `package example

func load() (*User, error) {
	user, err := find()
	if err != nil {
		return nil, nil
	}
	if user == nil {
		return nil, err
	}
	if err != nil && user != nil {
		return nil, err
	}
	return user, nil
}
`
	ctx := transformSource(t, src)

	if len(ctx.Ifs) != 3 {
		t.Fatalf("expected 3 if statements, got %d", len(ctx.Ifs))
	}

	first := ctx.Ifs[0]
	if !first.IsErrNotNil || first.ErrorVar != "err" {
		t.Fatalf("expected first if to be err != nil, got %#v", first)
	}
	if len(first.Returns) != 1 || strings.Join(first.Returns[0].Results, ",") != "nil,nil" {
		t.Fatalf("expected first if direct nil,nil return, got %#v", first.Returns)
	}

	second := ctx.Ifs[1]
	if second.IsErrNotNil {
		t.Fatalf("expected user nil check not to be err != nil, got %#v", second)
	}

	third := ctx.Ifs[2]
	if !third.IsErrNotNil || third.ErrorVar != "err" {
		t.Fatalf("expected compound condition to capture err != nil, got %#v", third)
	}
}

func TestTransformIfsAvoidsNonErrorNilChecks(t *testing.T) {
	src := `package example

func cached(cached *User, err error, other bool) (*User, error) {
	if cached != nil {
		return cached, nil
	}
	if err != nil || other {
		return nil, nil
	}
	if readErr != nil {
		return nil, nil
	}
	return nil, err
}
`
	ctx := transformSource(t, src)

	if len(ctx.Ifs) != 3 {
		t.Fatalf("expected 3 if statements, got %d", len(ctx.Ifs))
	}
	if ctx.Ifs[0].IsErrNotNil {
		t.Fatalf("expected cached nil check not to be treated as err check, got %#v", ctx.Ifs[0])
	}
	if ctx.Ifs[1].IsErrNotNil {
		t.Fatalf("expected OR condition not to be treated as definite err check, got %#v", ctx.Ifs[1])
	}
	if !ctx.Ifs[2].IsErrNotNil || ctx.Ifs[2].ErrorVar != "readErr" {
		t.Fatalf("expected readErr nil check to be treated as err check, got %#v", ctx.Ifs[2])
	}
}

func TestTransformIfsIgnoreFunctionLiterals(t *testing.T) {
	src := `package example

func outer(err error) error {
	fn := func() error {
		if err != nil {
			return nil
		}
		return err
	}
	return fn()
}
`
	ctx := transformSource(t, src)

	if len(ctx.Ifs) != 0 {
		t.Fatalf("expected ifs inside function literals to be ignored, got %#v", ctx.Ifs)
	}
}

func TestTransformComments(t *testing.T) {
	src := `package example

// Package TODO should be visible.
/*
 * Block comment line.
 * Second block line.
 */
func example() {}
`
	ctx := transformSource(t, src)

	if len(ctx.Comments) != 3 {
		t.Fatalf("expected 3 comments, got %d", len(ctx.Comments))
	}
	if ctx.Comments[0].Text != "Package TODO should be visible." {
		t.Fatalf("expected first comment text, got %q", ctx.Comments[0].Text)
	}
	if ctx.Comments[0].Raw != "// Package TODO should be visible." || !ctx.Comments[0].IsFirstLine {
		t.Fatalf("expected raw first line comment metadata, got raw=%q first=%v", ctx.Comments[0].Raw, ctx.Comments[0].IsFirstLine)
	}
	if ctx.Comments[1].Text != "Block comment line." {
		t.Fatalf("expected cleaned block comment text, got %q", ctx.Comments[1].Text)
	}
	if !ctx.Comments[1].IsFirstLine || ctx.Comments[2].IsFirstLine {
		t.Fatalf("expected only first block comment line to be marked first, got first=%v second=%v", ctx.Comments[1].IsFirstLine, ctx.Comments[2].IsFirstLine)
	}
}

func TestTransformLiterals(t *testing.T) {
	src := `package example

func score() int {
	return -42
}
`
	ctx := transformSource(t, src)

	if len(ctx.Literals) != 1 {
		t.Fatalf("expected 1 literal, got %d", len(ctx.Literals))
	}
	if ctx.Literals[0].Kind != "int" || ctx.Literals[0].Value != "-42" {
		t.Fatalf("expected int literal -42, got %#v", ctx.Literals[0])
	}
	if ctx.Literals[0].InFunction != "score" {
		t.Fatalf("expected literal in score, got %q", ctx.Literals[0].InFunction)
	}
}

func TestTransformCompositeLiterals(t *testing.T) {
	src := `package example

type User struct {
	Name string
}

var defaultUser = User{}

func build() {
	_ = User{Name: "a"}
	_ = []string{"a"}
	_ = map[string]int{"a": 1}
}
`
	ctx := transformSource(t, src)

	if len(ctx.CompositeLiterals) != 4 {
		t.Fatalf("expected 4 composite literals, got %d: %#v", len(ctx.CompositeLiterals), ctx.CompositeLiterals)
	}

	defaultUser := ctx.CompositeLiterals[0]
	if defaultUser.Type != "User" || defaultUser.TypeKind != "unknown" || defaultUser.InFunction != "" {
		t.Fatalf("expected package-level User literal, got %#v", defaultUser)
	}

	user := ctx.CompositeLiterals[1]
	if user.Type != "User" || user.InFunction != "build" {
		t.Fatalf("expected build User literal, got %#v", user)
	}
	if len(user.Fields) != 1 || user.Fields[0] != "Name" {
		t.Fatalf("expected User literal field Name, got %#v", user.Fields)
	}

	slice := ctx.CompositeLiterals[2]
	if slice.Type != "[]string" || slice.TypeKind != "slice" || slice.InFunction != "build" {
		t.Fatalf("expected build []string slice literal, got %#v", slice)
	}

	mapLit := ctx.CompositeLiterals[3]
	if mapLit.Type != "map[string]int" || mapLit.TypeKind != "map" || mapLit.InFunction != "build" {
		t.Fatalf("expected build map literal, got %#v", mapLit)
	}
	if len(mapLit.Fields) != 0 {
		t.Fatalf("expected map literal fields to be empty, got %#v", mapLit.Fields)
	}
}

func TestBuildPackageContextAggregatesCompositeLiterals(t *testing.T) {
	files := []*model.CodeContext{
		{
			ModulePath: "example.com/mod",
			Package: model.PackageInfo{
				Name: "example",
				Path: "example.com/mod/example",
			},
			CompositeLiterals: []model.CompositeLiteralInfo{{Type: "User"}},
			TypeUsages:        []model.TypeUsageInfo{{TypeName: "User"}},
			FieldAccess:       []model.FieldAccessInfo{{Field: "Name"}},
		},
	}

	pkg := transformer.BuildPackageContext(files)
	if len(pkg.AllCompositeLiterals) != 1 {
		t.Fatalf("expected 1 package composite literal, got %d", len(pkg.AllCompositeLiterals))
	}
	if len(pkg.AllTypeUsages) != 1 {
		t.Fatalf("expected 1 package type usage, got %d", len(pkg.AllTypeUsages))
	}
	if len(pkg.AllFieldAccesses) != 1 {
		t.Fatalf("expected 1 package field access, got %d", len(pkg.AllFieldAccesses))
	}
}

func TestTransformLines(t *testing.T) {
	src := `package example

func short() {}
`
	ctx := transformSourceFromFile(t, src)

	if len(ctx.Lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(ctx.Lines))
	}
	if ctx.Lines[1].Number != 2 || ctx.Lines[1].Length != 0 {
		t.Fatalf("expected blank second line, got %#v", ctx.Lines[1])
	}
	if ctx.Lines[2].Number != 3 || ctx.Lines[2].Length != len("func short() {}") {
		t.Fatalf("expected function line length, got %#v", ctx.Lines[2])
	}
}

func TestTransformLinesHandlesFinalLineWithoutTrailingNewline(t *testing.T) {
	line := "func exactlyLong() { println(\"" + strings.Repeat("x", 121) + "\") }"
	src := "package example\n" + line
	ctx := transformSourceFromFile(t, src)

	last := ctx.Lines[len(ctx.Lines)-1]
	if last.Length != len(line) {
		t.Fatalf("expected exact final line length, got %#v", last)
	}
}

func TestTransformLinesHandlesCRLF(t *testing.T) {
	src := "package example\r\nfunc short() {}\r\n"
	ctx := transformSourceFromFile(t, src)

	if ctx.Lines[0].Length != len("package example") {
		t.Fatalf("expected CRLF package line length without terminator, got %#v", ctx.Lines[0])
	}
	if ctx.Lines[1].Length != len("func short() {}") {
		t.Fatalf("expected CRLF function line length without terminator, got %#v", ctx.Lines[1])
	}
}

func TestTransformBlankAssignments(t *testing.T) {
	src := `package example

func assign() {
	_, _, value := values()
	_ = value
	fn := func() {
		_, _ = nested()
	}
	fn()
}
`
	ctx := transformSource(t, src)

	if len(ctx.BlankAssignments) != 2 {
		t.Fatalf("expected 2 blank assignments, got %d", len(ctx.BlankAssignments))
	}
	if ctx.BlankAssignments[0].BlankCount != 2 || ctx.BlankAssignments[0].TotalCount != 3 {
		t.Fatalf("expected first assignment to have 2 blanks out of 3, got %#v", ctx.BlankAssignments[0])
	}
	if ctx.BlankAssignments[1].BlankCount != 1 || ctx.BlankAssignments[1].InFunction != "assign" {
		t.Fatalf("expected second assignment in assign with one blank, got %#v", ctx.BlankAssignments[1])
	}
}

func TestTransformMakeAppendFacts(t *testing.T) {
	src := `package example

func build(n int, values []int) []int {
	items := make([]int, n)
	items = append(items, values...)
	var names = make([]string, 0, n)
	names = append(names, "x")
	other := make(map[string]int, n)
	_ = other
	fn := func() {
		nested := make([]int, 10)
		nested = append(nested, 1)
	}
	fn()
	return items
}
`
	ctx := transformSource(t, src)

	if len(ctx.MakeSlices) != 2 {
		t.Fatalf("expected 2 make slice facts, got %#v", ctx.MakeSlices)
	}
	if ctx.MakeSlices[0].Target != "items" || ctx.MakeSlices[0].LenArg != "n" || ctx.MakeSlices[0].HasCap {
		t.Fatalf("expected items make without cap, got %#v", ctx.MakeSlices[0])
	}
	if ctx.MakeSlices[1].Target != "names" || ctx.MakeSlices[1].LenArg != "0" || ctx.MakeSlices[1].CapArg != "n" {
		t.Fatalf("expected names make with cap, got %#v", ctx.MakeSlices[1])
	}

	if len(ctx.Appends) != 2 {
		t.Fatalf("expected 2 append facts, got %#v", ctx.Appends)
	}
	if ctx.Appends[0].Target != "items" || ctx.Appends[0].Source != "items" || ctx.Appends[0].InFunction != "build" {
		t.Fatalf("expected append to items, got %#v", ctx.Appends[0])
	}
	if ctx.Appends[1].Target != "names" || ctx.Appends[1].Source != "names" {
		t.Fatalf("expected append to names, got %#v", ctx.Appends[1])
	}
}

func TestTransformResourceFacts(t *testing.T) {
	src := `package example

import (
	"database/sql"
	"net/http"
)

func resources(db *sql.DB, client *http.Client) error {
	resp, err := http.Get("https://example.com")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	resp2, err := client.Do(req)
	if err != nil {
		return err
	}
	resp2.Body.Close()

	resp3, err := client.Get("https://example.com")
	if err != nil {
		return err
	}
	defer resp3.Body.Close()

	rows, err := db.Query("select 1")
	if err != nil {
		return err
	}
	defer rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	stmt, err := db.Prepare("select 1")
	if err != nil {
		return err
	}
	stmt.Close()

	job, _ := worker.Do(ctx)
	result, _ := search.Query(q)
	tmpl, _ := engine.Prepare(src)
	_, _, _ = job, result, tmpl

	fn := func() {
		nested, _ := http.Get("https://nested.example")
		defer nested.Body.Close()
	}
	fn()
	return nil
}
`
	ctx := transformSource(t, src)

	if len(ctx.ResourceAcquires) != 5 {
		t.Fatalf("expected 5 resource acquisitions, got %#v", ctx.ResourceAcquires)
	}
	if ctx.ResourceAcquires[0].Kind != "http_response" || ctx.ResourceAcquires[0].Target != "resp" {
		t.Fatalf("expected resp http response acquisition, got %#v", ctx.ResourceAcquires[0])
	}
	if ctx.ResourceAcquires[1].Kind != "http_response" || ctx.ResourceAcquires[1].Target != "resp2" {
		t.Fatalf("expected resp2 http response acquisition, got %#v", ctx.ResourceAcquires[1])
	}
	if ctx.ResourceAcquires[2].Kind != "http_response" || ctx.ResourceAcquires[2].Target != "resp3" {
		t.Fatalf("expected resp3 http response acquisition, got %#v", ctx.ResourceAcquires[2])
	}
	if ctx.ResourceAcquires[3].Kind != "sql_rows" || ctx.ResourceAcquires[3].Target != "rows" {
		t.Fatalf("expected rows acquisition, got %#v", ctx.ResourceAcquires[3])
	}
	if ctx.ResourceAcquires[4].Kind != "sql_stmt" || ctx.ResourceAcquires[4].Target != "stmt" {
		t.Fatalf("expected stmt acquisition, got %#v", ctx.ResourceAcquires[4])
	}

	if len(ctx.ResourceCloses) != 5 {
		t.Fatalf("expected 5 resource closes, got %#v", ctx.ResourceCloses)
	}
	if ctx.ResourceCloses[0].Target != "resp.Body" || !ctx.ResourceCloses[0].IsDefer {
		t.Fatalf("expected deferred resp.Body close, got %#v", ctx.ResourceCloses[0])
	}
	if ctx.ResourceCloses[1].Target != "resp2.Body" || ctx.ResourceCloses[1].IsDefer {
		t.Fatalf("expected direct resp2.Body close, got %#v", ctx.ResourceCloses[1])
	}
	if ctx.ResourceCloses[2].Target != "resp3.Body" || !ctx.ResourceCloses[2].IsDefer {
		t.Fatalf("expected deferred resp3.Body close, got %#v", ctx.ResourceCloses[2])
	}
	if ctx.ResourceCloses[3].Target != "rows" || !ctx.ResourceCloses[3].IsDefer {
		t.Fatalf("expected deferred rows close, got %#v", ctx.ResourceCloses[3])
	}
	if ctx.ResourceCloses[4].Target != "stmt" || ctx.ResourceCloses[4].IsDefer {
		t.Fatalf("expected direct stmt close, got %#v", ctx.ResourceCloses[4])
	}

	if len(ctx.ResourceErrs) != 1 || ctx.ResourceErrs[0].Target != "rows" || !ctx.ResourceErrs[0].IsChecked {
		t.Fatalf("expected rows Err fact, got %#v", ctx.ResourceErrs)
	}
}

func TestTransformResourceErrChecksFromConditions(t *testing.T) {
	src := `package example

func checkRows(rows Rows) error {
	if rows.Err() != nil {
		return rows.Err()
	}
	if errors.Is(rows.Err(), errDone) {
		return errDone
	}
	_ = rows.Err()
	rows.Err()
	if _ = rows.Err(); true {
		return nil
	}
	if rows.Err(); true {
		return nil
	}
	return nil
}
`
	ctx := transformSource(t, src)

	if len(ctx.ResourceErrs) != 7 {
		t.Fatalf("expected 7 rows Err facts, got %#v", ctx.ResourceErrs)
	}
	if ctx.ResourceErrs[0].Target != "rows" || !ctx.ResourceErrs[0].IsChecked {
		t.Fatalf("expected direct condition rows Err checked, got %#v", ctx.ResourceErrs[0])
	}
	if ctx.ResourceErrs[1].Target != "rows" || !ctx.ResourceErrs[1].IsChecked {
		t.Fatalf("expected returned rows Err checked, got %#v", ctx.ResourceErrs[1])
	}
	if ctx.ResourceErrs[2].Target != "rows" || !ctx.ResourceErrs[2].IsChecked {
		t.Fatalf("expected nested condition rows Err checked, got %#v", ctx.ResourceErrs[2])
	}
	if ctx.ResourceErrs[3].Target != "rows" || ctx.ResourceErrs[3].IsChecked {
		t.Fatalf("expected blank-assigned rows Err unchecked, got %#v", ctx.ResourceErrs[3])
	}
	if ctx.ResourceErrs[4].Target != "rows" || ctx.ResourceErrs[4].IsChecked {
		t.Fatalf("expected bare rows Err unchecked, got %#v", ctx.ResourceErrs[4])
	}
	if ctx.ResourceErrs[5].Target != "rows" || ctx.ResourceErrs[5].IsChecked {
		t.Fatalf("expected if-init blank rows Err unchecked, got %#v", ctx.ResourceErrs[5])
	}
	if ctx.ResourceErrs[6].Target != "rows" || ctx.ResourceErrs[6].IsChecked {
		t.Fatalf("expected if-init bare rows Err unchecked, got %#v", ctx.ResourceErrs[6])
	}
}

func TestTransformSubtests(t *testing.T) {
	src := `package example

import "testing"

func TestThing(t *testing.T) {
	t.Run("child", func(t *testing.T) {
		t.Parallel()
	})
	t.Run("serial", func(st *testing.T) {
		st.Log("serial")
	})
	t.Run(name, func(t *testing.T) {
		t.Parallel()
	})
	t.Run("not-test-param", func(x string) {})
}
`
	ctx := transformSource(t, src)

	if len(ctx.Subtests) != 3 {
		t.Fatalf("expected 3 subtests, got %#v", ctx.Subtests)
	}
	if ctx.Subtests[0].Name != "child" || ctx.Subtests[0].Function != "TestThing" ||
		ctx.Subtests[0].TestParam != "t" || !ctx.Subtests[0].HasParallel {
		t.Fatalf("expected parallel child subtest, got %#v", ctx.Subtests[0])
	}
	if ctx.Subtests[1].Name != "serial" || ctx.Subtests[1].TestParam != "st" ||
		ctx.Subtests[1].HasParallel {
		t.Fatalf("expected serial subtest, got %#v", ctx.Subtests[1])
	}
	if ctx.Subtests[2].Name != "" || !ctx.Subtests[2].HasParallel {
		t.Fatalf("expected dynamic named parallel subtest, got %#v", ctx.Subtests[2])
	}
}

func TestTransformTypeAssertions(t *testing.T) {
	src := `package example

var packageUnchecked = packageValue.(string)
var packageChecked, packageOK = packageValue.(int)
var packageWrapped = use(packageValue.(byte))
var packageChained = packageValue.(interface{ Done() }).(done)

func assert(value any) any {
	checked, ok := value.(string)
	unchecked := value.(int)
	var declared, declaredOK = value.(byte)
	_ = ok
	_ = declared
	_ = declaredOK
	wrapped := use(value.(rune))
	_ = wrapped
	chained := use(value.(interface{ Done() }).(done))
	_ = chained
	use(value.(float64))
	return value.(bool)
}
`
	ctx := transformSource(t, src)

	if len(ctx.TypeAssertions) != 13 {
		t.Fatalf("expected 13 type assertions, got %d", len(ctx.TypeAssertions))
	}

	packageUnchecked := ctx.TypeAssertions[0]
	if packageUnchecked.Context != "var" || packageUnchecked.IsCommaOK || packageUnchecked.InFunction != "" {
		t.Fatalf("expected unchecked package var assertion, got %#v", packageUnchecked)
	}

	packageChecked := ctx.TypeAssertions[1]
	if !packageChecked.IsCommaOK || packageChecked.ValueTarget != "packageChecked" || packageChecked.OKTarget != "packageOK" {
		t.Fatalf("expected comma-ok package var assertion, got %#v", packageChecked)
	}

	packageWrapped := ctx.TypeAssertions[2]
	if packageWrapped.Context != "var" || packageWrapped.AssertedType != "byte" {
		t.Fatalf("expected nested package var assertion, got %#v", packageWrapped)
	}

	packageOuter := ctx.TypeAssertions[3]
	packageInner := ctx.TypeAssertions[4]
	if packageOuter.AssertedType != "done" || packageInner.AssertedType != "interface{}" {
		t.Fatalf("expected chained package var assertions, got %#v %#v", packageOuter, packageInner)
	}

	checked := ctx.TypeAssertions[5]
	if !checked.IsCommaOK || checked.ValueTarget != "checked" || checked.OKTarget != "ok" || checked.AssertedType != "string" {
		t.Fatalf("expected comma-ok string assertion, got %#v", checked)
	}

	unchecked := ctx.TypeAssertions[6]
	if unchecked.IsCommaOK || unchecked.Context != "assign" || unchecked.AssertedType != "int" {
		t.Fatalf("expected unchecked int assignment assertion, got %#v", unchecked)
	}

	declared := ctx.TypeAssertions[7]
	if !declared.IsCommaOK || declared.Context != "var" || declared.ValueTarget != "declared" || declared.OKTarget != "declaredOK" {
		t.Fatalf("expected comma-ok var declaration assertion, got %#v", declared)
	}

	nested := ctx.TypeAssertions[8]
	if nested.Context != "call_arg" || nested.AssertedType != "rune" {
		t.Fatalf("expected nested rune call-arg assertion to be captured, got %#v", nested)
	}

	outer := ctx.TypeAssertions[9]
	inner := ctx.TypeAssertions[10]
	if outer.AssertedType != "done" || inner.AssertedType != "interface{}" {
		t.Fatalf("expected chained assertions to include outer and inner, got %#v %#v", outer, inner)
	}

	callArg := ctx.TypeAssertions[11]
	if callArg.Context != "call_arg" || callArg.AssertedType != "float64" {
		t.Fatalf("expected float64 call-arg assertion, got %#v", callArg)
	}

	ret := ctx.TypeAssertions[12]
	if ret.Context != "return" || ret.AssertedType != "bool" {
		t.Fatalf("expected bool return assertion, got %#v", ret)
	}
}

func TestTransformTypeAssertionsIgnoresFunctionLiterals(t *testing.T) {
	src := `package example

func outer(value any) {
	fn := func() {
		_ = value.(string)
	}
	fn()
}
`
	ctx := transformSource(t, src)

	if len(ctx.TypeAssertions) != 0 {
		t.Fatalf("expected nested func literal assertions to be ignored, got %#v", ctx.TypeAssertions)
	}
}

func TestTransformRangeLoopFacts(t *testing.T) {
	src := `package example

func process(items []string) {
	for idx, item := range items {
		idx := idx
		var item = item
		_ = idx
		_ = item
	}
	for _, name := range items {
		name := name
		_ = name
	}
}
`
	ctx := transformSource(t, src)

	if len(ctx.RangeLoops) != 2 {
		t.Fatalf("expected 2 range loops, got %d", len(ctx.RangeLoops))
	}
	if ctx.RangeLoops[0].Key != "idx" || ctx.RangeLoops[0].Value != "item" {
		t.Fatalf("unexpected first range loop: %#v", ctx.RangeLoops[0])
	}
	if ctx.RangeLoops[0].Position.Line != 4 || ctx.RangeLoops[0].EndLine != 9 {
		t.Fatalf("unexpected first range loop position: %#v", ctx.RangeLoops[0])
	}
	if ctx.RangeLoops[1].Key != "" || ctx.RangeLoops[1].Value != "name" {
		t.Fatalf("unexpected second range loop: %#v", ctx.RangeLoops[1])
	}

	if len(ctx.LoopVarCopies) != 3 {
		t.Fatalf("expected 3 loop var copies, got %#v", ctx.LoopVarCopies)
	}
	want := map[string]string{"idx": "key", "item": "value", "name": "value"}
	for _, copyInfo := range ctx.LoopVarCopies {
		if want[copyInfo.Variable] != copyInfo.Kind {
			t.Fatalf("unexpected loop var copy: %#v", copyInfo)
		}
	}
}

func TestTransformRangeLoopCopiesIgnoreNestedFunctionsAndRanges(t *testing.T) {
	src := `package example

func process(items []string, nested []string) {
	for _, item := range items {
		fn := func() {
			item := item
			_ = item
		}
		fn()
		for _, child := range nested {
			child := child
			_ = child
		}
	}
}
`
	ctx := transformSource(t, src)

	if len(ctx.RangeLoops) != 2 {
		t.Fatalf("expected outer and nested range loops, got %#v", ctx.RangeLoops)
	}
	if len(ctx.LoopVarCopies) != 1 {
		t.Fatalf("expected only nested range copy, got %#v", ctx.LoopVarCopies)
	}
	if ctx.LoopVarCopies[0].Variable != "child" {
		t.Fatalf("expected child copy, got %#v", ctx.LoopVarCopies[0])
	}
}

func TestTransformRangeLoopCopiesAvoidShadowedVariables(t *testing.T) {
	src := `package example

func process(items []string) {
	for _, item := range items {
		if item := lookup(); item != "" {
			item := item
			_ = item
		}
	}
}

func lookup() string { return "" }
`
	ctx := transformSource(t, src)

	if len(ctx.LoopVarCopies) != 0 {
		t.Fatalf("expected shadowed loop variable copies to be ignored, got %#v", ctx.LoopVarCopies)
	}
}

func TestTransformRangeLoopCopiesKeepIfBranchScopesSeparate(t *testing.T) {
	src := `package example

func process(items []string, cond bool) {
	for _, item := range items {
		if cond {
			item := other()
			_ = item
		} else {
			item := item
			_ = item
		}
	}
}

func other() string { return "" }
`
	ctx := transformSource(t, src)

	if len(ctx.LoopVarCopies) != 1 {
		t.Fatalf("expected else branch loop var copy, got %#v", ctx.LoopVarCopies)
	}
	if ctx.LoopVarCopies[0].Variable != "item" {
		t.Fatalf("expected item copy, got %#v", ctx.LoopVarCopies[0])
	}
}

func TestTransformRangeLoopCopiesAvoidSelectReceiveShadow(t *testing.T) {
	src := `package example

func process(items []string, ch <-chan string) {
	for _, item := range items {
		select {
		case item := <-ch:
			item := item
			_ = item
		}
	}
}
`
	ctx := transformSource(t, src)

	if len(ctx.LoopVarCopies) != 0 {
		t.Fatalf("expected select receive shadow to be ignored, got %#v", ctx.LoopVarCopies)
	}
}

func transformSource(t *testing.T, src string) *model.CodeContext {
	t.Helper()
	return transformSourceWithFilename(t, src, "test.go")
}

func transformSourceFromFile(t *testing.T, src string) *model.CodeContext {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "test.go")
	if err := os.WriteFile(filePath, []byte(src), 0o600); err != nil {
		t.Fatalf("writing source: %v", err)
	}
	return transformSourceWithFilename(t, src, filePath)
}

func transformSourceWithFilename(t *testing.T, src, fileName string) *model.CodeContext {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fileName, src, parser.ParseComments)
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
	return trans.Transform(file, fileName)
}
