package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/burdzwastaken/regolint/internal/evaluator"
	"github.com/burdzwastaken/regolint/internal/model"
	"github.com/burdzwastaken/regolint/internal/nolint"
	"github.com/burdzwastaken/regolint/internal/output"
	"github.com/burdzwastaken/regolint/internal/transformer"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	policyDir   = flag.String("policy-dir", "./policies", "directory containing .rego policy files")
	disabled    = flag.String("disabled", "", "comma-separated list of rule IDs to disable")
	exclude     = flag.String("exclude", "", "comma-separated list of file patterns to exclude")
	format      = flag.String("format", "text", "output format: text, json, sarif")
	debug       = flag.Bool("debug", false, "enable debug output")
	dryRun      = flag.Bool("dry-run", false, "show input without evaluating")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// ErrViolationsFound is returned when policy violations are detected.
var ErrViolationsFound = errors.New("violations found")

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("regolint %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: regolint [flags] <packages>")
		os.Exit(1)
	}

	if err := run(); err != nil {
		if errors.Is(err, ErrViolationsFound) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

func run() error {
	policies, err := loadPolicies(*policyDir)
	if err != nil {
		return fmt.Errorf("loading policies: %w", err)
	}

	if len(policies) == 0 {
		fmt.Fprintln(os.Stderr, "warning: no policies found")
		return nil
	}

	eval, err := evaluator.New(policies)
	if err != nil {
		return fmt.Errorf("creating evaluator: %w", err)
	}

	pkgPatterns := flag.Args()
	pkgs, err := loadPackages(pkgPatterns)
	if err != nil {
		return fmt.Errorf("loading packages: %w", err)
	}

	disabledRules := parseList(*disabled)
	excludePatterns := parseList(*exclude)

	var allViolations []model.Violation

	for _, pkg := range pkgs {
		violations, err := analyzePackage(pkg, eval, pkg.PkgPath, disabledRules, excludePatterns)
		if err != nil {
			return err
		}
		allViolations = append(allViolations, violations...)
	}

	if err := outputResults(allViolations); err != nil {
		return err
	}
	if len(allViolations) > 0 {
		return ErrViolationsFound
	}
	return nil
}

func loadPolicies(dir string) (map[string]string, error) {
	policies := make(map[string]string)

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".rego" {
			return nil
		}
		if strings.HasSuffix(path, "_test.rego") {
			return nil
		}

		content, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		policies[path] = string(content)
		return nil
	})

	if os.IsNotExist(err) {
		return policies, nil
	}

	return policies, err
}

func parseList(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func loadPackages(patterns []string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo,
	}
	return packages.Load(cfg, patterns...)
}

func analyzePackage(pkg *packages.Package, eval *evaluator.Evaluator, modulePath string, disabledRules, excludePatterns []string) ([]model.Violation, error) {
	var violations []model.Violation

	fset := token.NewFileSet()

	pass := &analysis.Pass{
		Fset: fset,
		Pkg:  pkg.Types,
	}

	trans := transformer.New(pass, modulePath)

	for _, filePath := range pkg.GoFiles {
		if shouldSkip(filePath, excludePatterns) {
			continue
		}

		file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", filePath, err)
		}

		codeCtx := trans.Transform(file, filePath)

		if *dryRun {
			data, _ := json.MarshalIndent(codeCtx, "", "  ")
			fmt.Printf("=== %s ===\n%s\n\n", filePath, data)
			continue
		}

		if *debug {
			data, _ := json.MarshalIndent(codeCtx, "", "  ")
			fmt.Fprintf(os.Stderr, "DEBUG: %s\n%s\n", filePath, data)
		}

		fileViolations, err := eval.Evaluate(context.Background(), codeCtx)
		if err != nil {
			return nil, fmt.Errorf("evaluating %s: %w", filePath, err)
		}

		var filtered []model.Violation
		for _, v := range fileViolations {
			if !isDisabled(v.Rule, disabledRules) {
				v.Position.File = filePath
				filtered = append(filtered, v)
			}
		}

		filtered = nolint.FilterModelViolations(filtered, codeCtx.Nolints)

		violations = append(violations, filtered...)
	}

	return violations, nil
}

func shouldSkip(filePath string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := doublestar.Match(pattern, filePath)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func isDisabled(rule string, disabled []string) bool {
	return slices.Contains(disabled, rule)
}

func outputResults(violations []model.Violation) error {
	if len(violations) == 0 {
		return nil
	}

	switch *format {
	case "json":
		data, err := json.MarshalIndent(violations, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case "sarif":
		if err := output.WriteSARIF(os.Stdout, violations, version); err != nil {
			return err
		}
	default:
		for _, v := range violations {
			severity := v.Severity
			if severity == "" {
				severity = "error"
			}
			fmt.Printf("%s:%d:%d: %s [%s] %s\n",
				v.Position.File, v.Position.Line, v.Position.Column,
				severity, v.Rule, v.Message)
		}
	}

	return nil
}
