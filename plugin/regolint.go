package plugin

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"log"
	"sync"

	"github.com/burdzwastaken/regolint/internal/config"
	"github.com/burdzwastaken/regolint/internal/evaluator"
	"github.com/burdzwastaken/regolint/internal/model"
	"github.com/burdzwastaken/regolint/internal/nolint"
	"github.com/burdzwastaken/regolint/internal/transformer"
	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
)

const (
	name = "regolint"
	doc  = "Policy-as-code for Go. Write lint rules in Rego, not Go."
)

func init() {
	register.Plugin(name, New)
}

// Settings mirrors config options for golangci-lint integration.
type Settings struct {
	PolicyDir   string   `json:"policy-dir"`
	PolicyFiles []string `json:"policy-files"`
	Disabled    []string `json:"disabled"`
	Exclude     []string `json:"exclude"`
}

// RegolintPlugin implements register.LinterPlugin.
type RegolintPlugin struct {
	settings Settings
}

// New creates a new regolint plugin instance with validated settings.
func New(settings any) (register.LinterPlugin, error) {
	s, err := register.DecodeSettings[Settings](settings)
	if err != nil {
		return nil, fmt.Errorf("decoding settings: %w", err)
	}
	return &RegolintPlugin{settings: s}, nil
}

// BuildAnalyzers returns the regolint analyzer.
func (p *RegolintPlugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	var (
		evalOnce sync.Once
		eval     *evaluator.Evaluator
		evalErr  error
		cfg      *config.Config
	)

	analyzer := &analysis.Analyzer{
		Name: name,
		Doc:  doc,
		Run: func(pass *analysis.Pass) (any, error) {
			evalOnce.Do(func() {
				cfg = p.buildConfig()

				policies, err := cfg.LoadPolicies()
				if err != nil {
					evalErr = err
					return
				}

				if len(policies) == 0 {
					log.Printf("[regolint] warning: no policies found in %s", cfg.Policies.Directory)
					return
				}

				eval, evalErr = evaluator.New(policies)
			})

			if evalErr != nil {
				return nil, evalErr
			}

			if eval == nil {
				return nil, nil
			}

			// Use pass.Pkg.Path() directly - the standard approach for linters
			modulePath := pass.Pkg.Path()
			trans := transformer.New(pass, modulePath)

			for _, file := range pass.Files {
				filePath := pass.Fset.Position(file.Pos()).Filename

				if cfg.ShouldSkip(filePath) {
					continue
				}

				codeCtx := trans.Transform(file, filePath)

				violations, err := eval.Evaluate(context.Background(), codeCtx)
				if err != nil {
					return nil, fmt.Errorf("evaluating %s: %w", filePath, err)
				}

				var filtered []model.Violation
				for _, v := range violations {
					if !cfg.IsRuleDisabled(v.Rule) {
						filtered = append(filtered, v)
					}
				}

				filtered = nolint.FilterModelViolations(filtered, codeCtx.Nolints)

				for _, v := range filtered {
					pos := findPosition(pass, file, v.Position.Line)
					pass.Reportf(pos, "[%s] %s", v.Rule, v.Message)
				}
			}

			return nil, nil
		},
	}

	return []*analysis.Analyzer{analyzer}, nil
}

// GetLoadMode returns the load mode for the plugin.
func (p *RegolintPlugin) GetLoadMode() string {
	return register.LoadModeTypesInfo
}

func (p *RegolintPlugin) buildConfig() *config.Config {
	cfg := config.Default()
	cfg.Exclude = nil

	if p.settings.PolicyDir != "" {
		cfg.Policies.Directory = p.settings.PolicyDir
	}

	if len(p.settings.PolicyFiles) > 0 {
		cfg.Policies.Files = p.settings.PolicyFiles
	}

	if len(p.settings.Disabled) > 0 {
		cfg.Rules.Disabled = p.settings.Disabled
	}

	if len(p.settings.Exclude) > 0 {
		cfg.Exclude = p.settings.Exclude
	}

	return cfg
}

func findPosition(pass *analysis.Pass, file *ast.File, line int) token.Pos {
	best := file.Pos()
	var bestLine int

	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		pos := pass.Fset.Position(n.Pos())
		if pos.Line == line {
			best = n.Pos()
			return false
		}
		if pos.Line < line && pos.Line > bestLine {
			best = n.Pos()
			bestLine = pos.Line
		}
		return true
	})

	return best
}
