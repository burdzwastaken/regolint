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
	"strings"

	"github.com/burdzwastaken/regolint/internal/config"
	"github.com/burdzwastaken/regolint/internal/evaluator"
	"github.com/burdzwastaken/regolint/internal/model"
	"github.com/burdzwastaken/regolint/internal/nolint"
	"github.com/burdzwastaken/regolint/internal/output"
	"github.com/burdzwastaken/regolint/internal/transformer"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

var (
	version = "dev"     // nolint:gochecknoglobals
	commit  = "none"    // nolint:gochecknoglobals
	date    = "unknown" // nolint:gochecknoglobals
)

var (
	policyDir   = flag.String("policy-dir", "./policies", "directory containing .rego policy files") // nolint:gochecknoglobals,lll
	configPath  = flag.String("config", "", "optional regolint YAML config file")                    // nolint:gochecknoglobals,lll
	disabled    = flag.String("disabled", "", "comma-separated list of rule IDs to disable")         // nolint:gochecknoglobals,lll
	exclude     = flag.String("exclude", "", "comma-separated list of file patterns to exclude")     // nolint:gochecknoglobals,lll
	format      = flag.String("format", "text", "output format: text, json, sarif")                  // nolint:gochecknoglobals,lll
	debug       = flag.Bool("debug", false, "enable debug output")                                   // nolint:gochecknoglobals,lll
	dryRun      = flag.Bool("dry-run", false, "show input without evaluating")                       // nolint:gochecknoglobals,lll
	showVersion = flag.Bool("version", false, "print version and exit")                              // nolint:gochecknoglobals,lll
)

// ErrViolationsFound is returned when policy violations are detected.
var ErrViolationsFound = errors.New("violations found") // nolint:gochecknoglobals

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
	cfg, err := buildConfig()
	if err != nil {
		return err
	}

	policies, err := cfg.LoadPolicies()
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

	var allViolations []model.Violation

	for _, pkg := range pkgs {
		violations, err := analyzePackage(pkg, eval, pkg.PkgPath, cfg)
		if err != nil {
			return err
		}
		allViolations = append(allViolations, violations...)
	}

	if err := outputResults(allViolations, cfg.Output.Format); err != nil {
		return err
	}
	if len(allViolations) > 0 {
		return ErrViolationsFound
	}
	return nil
}

func buildConfig() (*config.Config, error) {
	var cfg *config.Config
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			return nil, err
		}
		cfg = loaded
	} else {
		cfg = config.Default()
		cfg.Policies.Directory = "./policies"
		cfg.Exclude = nil
	}

	if *policyDir != "./policies" || *configPath == "" {
		cfg.Policies.Directory = *policyDir
	}
	if *disabled != "" {
		cfg.Rules.Disabled = parseList(*disabled)
	}
	if *exclude != "" {
		cfg.Exclude = parseList(*exclude)
	}
	if *format != "text" {
		cfg.Output.Format = *format
	}

	return cfg, nil
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

// nolint:gocyclo,funlen
func analyzePackage(
	pkg *packages.Package,
	eval *evaluator.Evaluator,
	modulePath string,
	cfg *config.Config,
) ([]model.Violation, error) {
	var violations []model.Violation
	var codeContexts []*model.CodeContext

	fset := token.NewFileSet()

	pass := &analysis.Pass{
		Fset: fset,
		Pkg:  pkg.Types,
	}

	trans := transformer.New(pass, modulePath)
	nolintsByFile := make(map[string][]model.NolintDirective)

	for _, filePath := range pkg.GoFiles {
		if cfg.ShouldSkip(filePath) {
			continue
		}

		file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", filePath, err)
		}

		codeCtx := trans.Transform(file, filePath)
		codeCtx.RuleOptions = cfg.Rules.Options
		codeContexts = append(codeContexts, codeCtx)
		nolintsByFile[filepath.Base(filePath)] = codeCtx.Nolints

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
			if !cfg.IsRuleDisabled(v.Rule) {
				v.Position.File = filePath
				filtered = append(filtered, v)
			}
		}

		filtered = nolint.FilterModelViolations(filtered, codeCtx.Nolints)

		violations = append(violations, filtered...)
	}

	if *dryRun || len(codeContexts) == 0 {
		return violations, nil
	}

	pkgCtx := transformer.BuildPackageContext(codeContexts)
	packageViolations, err := eval.EvaluatePackage(context.Background(), pkgCtx)
	if err != nil {
		return nil, fmt.Errorf("evaluating package %s: %w", pkg.PkgPath, err)
	}

	for _, v := range packageViolations {
		if cfg.IsRuleDisabled(v.Rule) {
			continue
		}

		baseName := v.Position.File
		if baseName == "" {
			baseName = filepath.Base(codeContexts[0].FilePath)
		}

		v.Position.File = packageFilePath(baseName, codeContexts)
		filtered := nolint.FilterModelViolations([]model.Violation{v}, nolintsByFile[baseName])
		violations = append(violations, filtered...)
	}

	return violations, nil
}

func packageFilePath(baseName string, codeContexts []*model.CodeContext) string {
	for _, codeCtx := range codeContexts {
		if filepath.Base(codeCtx.FilePath) == baseName {
			return codeCtx.FilePath
		}
	}
	return baseName
}

func outputResults(violations []model.Violation, format string) error {
	if len(violations) == 0 {
		return nil
	}

	switch format {
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
