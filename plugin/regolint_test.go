package plugin

import (
	"testing"

	"github.com/golangci/plugin-module-register/register"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		settings any
		wantErr  bool
	}{
		{
			name:     "nil settings",
			settings: nil,
			wantErr:  false,
		},
		{
			name:     "empty map",
			settings: map[string]any{},
			wantErr:  false,
		},
		{
			name: "valid settings",
			settings: map[string]any{
				"policy-dir": "./policies",
				"disabled":   []string{"RULE001"},
			},
			wantErr: false,
		},
		{
			name: "with policy files",
			settings: map[string]any{
				"policy-files": []string{"a.rego", "b.rego"},
				"exclude":      []string{"*_test.go"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin, err := New(tt.settings)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && plugin == nil {
				t.Error("New() returned nil plugin")
			}
		})
	}
}

func TestRegolintPlugin_BuildAnalyzers(t *testing.T) {
	plugin, err := New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	analyzers, err := plugin.BuildAnalyzers()
	if err != nil {
		t.Fatalf("BuildAnalyzers() error = %v", err)
	}

	if len(analyzers) != 1 {
		t.Errorf("BuildAnalyzers() returned %d analyzers, want 1", len(analyzers))
	}

	if analyzers[0].Name != "regolint" {
		t.Errorf("Analyzer name = %q, want %q", analyzers[0].Name, "regolint")
	}

	if analyzers[0].Run == nil {
		t.Error("Analyzer Run function is nil")
	}
}

func TestRegolintPlugin_GetLoadMode(t *testing.T) {
	plugin, err := New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	p, ok := plugin.(*RegolintPlugin)
	if !ok {
		t.Fatal("plugin is not *RegolintPlugin")
	}

	mode := p.GetLoadMode()
	if mode != register.LoadModeTypesInfo {
		t.Errorf("GetLoadMode() = %q, want %q", mode, register.LoadModeTypesInfo)
	}
}

func TestRegolintPlugin_buildConfig(t *testing.T) {
	tests := []struct {
		name     string
		settings Settings
		check    func(*testing.T, *RegolintPlugin)
	}{
		{
			name:     "default config",
			settings: Settings{},
			check: func(t *testing.T, p *RegolintPlugin) {
				cfg := p.buildConfig()
				if cfg.Policies.Directory != ".regolint/policies" {
					t.Errorf("default policy dir = %q, want %q", cfg.Policies.Directory, ".regolint/policies")
				}
			},
		},
		{
			name: "custom policy dir",
			settings: Settings{
				PolicyDir: "/custom/policies",
			},
			check: func(t *testing.T, p *RegolintPlugin) {
				cfg := p.buildConfig()
				if cfg.Policies.Directory != "/custom/policies" {
					t.Errorf("policy dir = %q, want %q", cfg.Policies.Directory, "/custom/policies")
				}
			},
		},
		{
			name: "disabled rules",
			settings: Settings{
				Disabled: []string{"RULE001", "RULE002"},
			},
			check: func(t *testing.T, p *RegolintPlugin) {
				cfg := p.buildConfig()
				if len(cfg.Rules.Disabled) != 2 {
					t.Errorf("disabled rules count = %d, want 2", len(cfg.Rules.Disabled))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &RegolintPlugin{settings: tt.settings}
			tt.check(t, p)
		})
	}
}
