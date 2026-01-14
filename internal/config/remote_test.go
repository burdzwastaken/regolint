package config

import (
	"context"
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{"loopback IPv4", "127.0.0.1", true},
		{"loopback IPv6", "::1", true},
		{"private 10.x", "10.0.0.1", true},
		{"private 172.16.x", "172.16.0.1", true},
		{"private 192.168.x", "192.168.1.1", true},
		{"link-local IPv4", "169.254.1.1", true},
		{"link-local IPv6", "fe80::1", true},
		{"AWS metadata", "169.254.169.254", true},
		{"unspecified IPv4", "0.0.0.0", true},
		{"unspecified IPv6", "::", true},
		{"IPv4-mapped IPv6 loopback", "::ffff:127.0.0.1", true},
		{"IPv4-mapped IPv6 private", "::ffff:192.168.1.1", true},
		{"public IPv4", "8.8.8.8", false},
		{"public IPv6", "2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid IP: %s", tt.ip)
			}
			got := isBlockedIP(ip)
			if got != tt.blocked {
				t.Errorf("isBlockedIP(%s) = %v, want %v", tt.ip, got, tt.blocked)
			}
		})
	}
}

func TestIsBlockedHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		blocked bool
	}{
		{"localhost", "localhost", true},
		{"localhost uppercase", "LOCALHOST", true},
		{"localhost mixed case", "LocalHost", true},
		{"localhost with port", "localhost:8080", true},
		{"loopback IPv4", "127.0.0.1", true},
		{"loopback IPv4 with port", "127.0.0.1:443", true},
		{"private 10.x", "10.0.0.1", true},
		{"private 172.16.x", "172.16.0.1", true},
		{"private 192.168.x", "192.168.1.1", true},
		{"link-local", "169.254.1.1", true},
		{"AWS metadata", "169.254.169.254", true},
		{"loopback IPv6", "::1", true},
		{"unspecified", "0.0.0.0", true},
		{"public IP", "8.8.8.8", false},
		{"public domain", "example.com", false},
		{"github.com", "github.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBlockedHost(tt.host)
			if got != tt.blocked {
				t.Errorf("isBlockedHost(%q) = %v, want %v", tt.host, got, tt.blocked)
			}
		})
	}
}

func TestPolicyNameFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{"simple path", "https://example.com/policies/security.rego", "security.rego"},
		{"trailing slash", "https://example.com/policies/", "example.com.rego"},
		{"no path", "https://example.com", "example.com.rego"},
		{"root path", "https://example.com/", "example.com.rego"},
		{"deep path", "https://example.com/a/b/c/policy.rego", "policy.rego"},
		{"with query", "https://example.com/policy.rego?v=1", "policy.rego"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyNameFromURL(tt.url)
			if got != tt.expected {
				t.Errorf("policyNameFromURL(%q) = %q, want %q", tt.url, got, tt.expected)
			}
		})
	}
}

func TestFetchPolicyRequiresHTTPS(t *testing.T) {
	remote := RemotePolicy{URL: "http://example.com/policy.rego"}
	_, err := fetchPolicy(nil, remote)
	if err == nil {
		t.Error("expected error for HTTP URL, got nil")
	}
	if err != nil && !contains(err.Error(), "only https allowed") {
		t.Errorf("expected HTTPS error, got: %v", err)
	}
}

func TestFetchPolicyBlocksInternalHosts(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"localhost", "https://localhost/policy.rego"},
		{"loopback", "https://127.0.0.1/policy.rego"},
		{"private IP", "https://192.168.1.1/policy.rego"},
		{"AWS metadata", "https://169.254.169.254/policy.rego"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remote := RemotePolicy{URL: tt.url}
			_, err := fetchPolicy(nil, remote)
			if err == nil {
				t.Errorf("expected error for blocked host %s, got nil", tt.url)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestSafeDialContext_BlocksLocalhost(t *testing.T) {
	ctx := context.Background()
	_, err := safeDialContext(ctx, "tcp", "localhost:443")
	if err == nil {
		t.Error("expected error for localhost, got nil")
	}
	if err != nil && !contains(err.Error(), "blocked hostname") {
		t.Errorf("expected blocked hostname error, got: %v", err)
	}
}

func TestSafeDialContext_BlocksPrivateIP(t *testing.T) {
	ctx := context.Background()

	// Test with IP literal (no DNS resolution needed)
	_, err := safeDialContext(ctx, "tcp", "127.0.0.1:443")
	if err == nil {
		t.Error("expected error for loopback IP, got nil")
	}
}

func TestSafeDialContext_InvalidAddress(t *testing.T) {
	ctx := context.Background()
	_, err := safeDialContext(ctx, "tcp", "invalid-no-port")
	if err == nil {
		t.Error("expected error for invalid address, got nil")
	}
	if err != nil && !contains(err.Error(), "invalid address") {
		t.Errorf("expected invalid address error, got: %v", err)
	}
}
