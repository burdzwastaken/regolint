package evaluator

import (
	"regexp"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
)

const maxRegexCacheSize = 1000

var regexCache, _ = lru.New[string, *regexp.Regexp](maxRegexCacheSize)

func init() {
	registerBuiltins()
}

func registerBuiltins() {
	rego.RegisterBuiltin2(
		&rego.Function{
			Name:             "go.matches_pattern",
			Description:      "Checks if a string matches a regular expression pattern",
			Decl:             types.NewFunction(types.Args(types.S, types.S), types.B),
			Memoize:          true,
			Nondeterministic: false,
		},
		func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
			str, ok := a.Value.(ast.String)
			if !ok {
				return nil, nil
			}
			pattern, ok := b.Value.(ast.String)
			if !ok {
				return nil, nil
			}

			re, err := getCompiledRegex(string(pattern))
			if err != nil {
				return ast.BooleanTerm(false), nil
			}

			return ast.BooleanTerm(re.MatchString(string(str))), nil
		},
	)

	rego.RegisterBuiltin1(
		&rego.Function{
			Name:             "go.is_exported",
			Description:      "Checks if a Go identifier is exported (starts with uppercase)",
			Decl:             types.NewFunction(types.Args(types.S), types.B),
			Memoize:          true,
			Nondeterministic: false,
		},
		func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			str, ok := a.Value.(ast.String)
			if !ok || len(str) == 0 {
				return ast.BooleanTerm(false), nil
			}

			first := str[0]
			return ast.BooleanTerm(first >= 'A' && first <= 'Z'), nil
		},
	)

	rego.RegisterBuiltin1(
		&rego.Function{
			Name:             "go.is_test_file",
			Description:      "Checks if a filename is a Go test file",
			Decl:             types.NewFunction(types.Args(types.S), types.B),
			Memoize:          true,
			Nondeterministic: false,
		},
		func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			str, ok := a.Value.(ast.String)
			if !ok {
				return ast.BooleanTerm(false), nil
			}

			s := string(str)
			isTest := len(s) > 8 && s[len(s)-8:] == "_test.go"
			return ast.BooleanTerm(isTest), nil
		},
	)

	rego.RegisterBuiltin1(
		&rego.Function{
			Name:             "go.package_name",
			Description:      "Extracts the package name from an import path",
			Decl:             types.NewFunction(types.Args(types.S), types.S),
			Memoize:          true,
			Nondeterministic: false,
		},
		func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			str, ok := a.Value.(ast.String)
			if !ok {
				return nil, nil
			}

			s := string(str)
			for i := len(s) - 1; i >= 0; i-- {
				if s[i] == '/' {
					return ast.StringTerm(s[i+1:]), nil
				}
			}

			return ast.StringTerm(s), nil
		},
	)
}

func getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := regexCache.Get(pattern); ok {
		return cached, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCache.Add(pattern, re)
	return re, nil
}
