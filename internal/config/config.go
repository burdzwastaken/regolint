package config

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

// Config represents the regolint configuration.
type Config struct {
	Policies    PoliciesConfig    `yaml:"policies"`
	Rules       RulesConfig       `yaml:"rules"`
	Include     []string          `yaml:"include"`
	Exclude     []string          `yaml:"exclude"`
	Output      OutputConfig      `yaml:"output"`
	Performance PerformanceConfig `yaml:"performance"`
}

// PoliciesConfig specifies where to load policies from.
type PoliciesConfig struct {
	Directory string         `yaml:"directory"`
	Files     []string       `yaml:"files"`
	Remote    []RemotePolicy `yaml:"remote"`
}

// RemotePolicy specifies a policy to fetch from a URL.
type RemotePolicy struct {
	URL      string `yaml:"url"`
	Checksum string `yaml:"checksum"`
}

// RulesConfig allows rule customization.
type RulesConfig struct {
	Disabled []string          `yaml:"disabled"`
	Severity map[string]string `yaml:"severity"`
}

// OutputConfig controls output formatting.
type OutputConfig struct {
	Format  string `yaml:"format"`
	Verbose bool   `yaml:"verbose"`
}

// PerformanceConfig controls performance tuning.
type PerformanceConfig struct {
	CachePolicies bool   `yaml:"cache_policies"`
	Parallelism   int    `yaml:"parallelism"`
	Timeout       string `yaml:"timeout"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Policies: PoliciesConfig{
			Directory: ".regolint/policies",
		},
		Include: []string{"**/*.go"},
		Exclude: []string{
			"**/*_test.go",
			"**/vendor/**",
			"**/testdata/**",
		},
		Output: OutputConfig{
			Format: "text",
		},
		Performance: PerformanceConfig{
			CachePolicies: true,
			Parallelism:   4,
			Timeout:       "30s",
		},
	}
}

// Load reads configuration from a file.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}

// LoadPolicies reads all .rego files from configured locations.
func (c *Config) LoadPolicies() (map[string]string, error) {
	policies := make(map[string]string)

	if c.Policies.Directory != "" {
		if err := c.loadPoliciesFromDir(c.Policies.Directory, policies); err != nil {
			return nil, err
		}
	}

	for _, file := range c.Policies.Files {
		content, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			return nil, fmt.Errorf("reading policy %s: %w", file, err)
		}
		policies[filepath.Base(file)] = string(content)
	}

	remotePolicies, err := c.FetchRemotePolicies()
	if err != nil {
		return nil, err
	}
	maps.Copy(policies, remotePolicies)

	return policies, nil
}

func (c *Config) loadPoliciesFromDir(dir string, policies map[string]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading policy directory: %w", err)
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())

		if entry.IsDir() {
			if err := c.loadPoliciesFromDir(path, policies); err != nil {
				return err
			}
			continue
		}

		if filepath.Ext(entry.Name()) != ".rego" {
			continue
		}

		if strings.HasSuffix(entry.Name(), "_test.rego") {
			continue
		}

		content, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return fmt.Errorf("reading policy %s: %w", path, err)
		}

		policies[path] = string(content)
	}

	return nil
}

// IsRuleDisabled checks if a rule is disabled.
func (c *Config) IsRuleDisabled(ruleID string) bool {
	return slices.Contains(c.Rules.Disabled, ruleID)
}

// GetSeverity returns the configured severity for a rule.
func (c *Config) GetSeverity(ruleID, defaultSeverity string) string {
	if sev, ok := c.Rules.Severity[ruleID]; ok {
		return sev
	}
	return defaultSeverity
}

// ShouldSkip returns true if the file should be excluded from linting.
func (c *Config) ShouldSkip(filePath string) bool {
	for _, pattern := range c.Exclude {
		matched, err := doublestar.Match(pattern, filePath)
		if err == nil && matched {
			return true
		}
	}
	return false
}
