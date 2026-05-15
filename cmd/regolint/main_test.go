package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildConfigUsesConfiguredOutputFormat(t *testing.T) {
	resetFlags(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "regolint.yml")
	data := []byte(`output:
  format: json
policies:
  directory: ./custom-policies
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	*configPath = path

	cfg, err := buildConfig()
	if err != nil {
		t.Fatalf("building config: %v", err)
	}

	if cfg.Output.Format != "json" {
		t.Fatalf("output format = %q, want json", cfg.Output.Format)
	}
	if cfg.Policies.Directory != "./custom-policies" {
		t.Fatalf("policy directory = %q, want ./custom-policies", cfg.Policies.Directory)
	}
}

func TestBuildConfigFormatFlagOverridesConfig(t *testing.T) {
	resetFlags(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "regolint.yml")
	data := []byte(`output:
  format: json
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	*configPath = path
	*format = "sarif"

	cfg, err := buildConfig()
	if err != nil {
		t.Fatalf("building config: %v", err)
	}

	if cfg.Output.Format != "sarif" {
		t.Fatalf("output format = %q, want sarif", cfg.Output.Format)
	}
}

func resetFlags(t *testing.T) {
	t.Helper()

	originalPolicyDir := *policyDir
	originalConfigPath := *configPath
	originalDisabled := *disabled
	originalExclude := *exclude
	originalFormat := *format
	originalDebug := *debug
	originalDryRun := *dryRun
	originalShowVersion := *showVersion

	*policyDir = "./policies"
	*configPath = ""
	*disabled = ""
	*exclude = ""
	*format = "text"
	*debug = false
	*dryRun = false
	*showVersion = false

	t.Cleanup(func() {
		*policyDir = originalPolicyDir
		*configPath = originalConfigPath
		*disabled = originalDisabled
		*exclude = originalExclude
		*format = originalFormat
		*debug = originalDebug
		*dryRun = originalDryRun
		*showVersion = originalShowVersion
	})
}
