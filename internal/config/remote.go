package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

func (c *Config) FetchRemotePolicies() (map[string]string, error) {
	policies := make(map[string]string)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	for _, remote := range c.Policies.Remote {
		content, err := fetchPolicy(client, remote)
		if err != nil {
			return nil, err
		}

		name := policyNameFromURL(remote.URL)
		policies[name] = content
	}

	return policies, nil
}

const maxPolicySize = 10 * 1024 * 1024 // 10MB limit

func fetchPolicy(client *http.Client, remote RemotePolicy) (string, error) {
	u, err := url.Parse(remote.URL)
	if err != nil {
		return "", fmt.Errorf("invalid URL %s: %w", remote.URL, err)
	}

	if u.Scheme != "https" {
		return "", fmt.Errorf("insecure URL scheme %q: only https allowed", u.Scheme)
	}

	if isBlockedHost(u.Host) {
		return "", fmt.Errorf("blocked host %q: internal/private addresses not allowed", u.Host)
	}

	resp, err := client.Get(remote.URL)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", remote.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching %s: status %d", remote.URL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize+1))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", remote.URL, err)
	}

	if len(body) > maxPolicySize {
		return "", fmt.Errorf("policy %s exceeds maximum size of %d bytes", remote.URL, maxPolicySize)
	}

	if remote.Checksum == "" {
		fmt.Fprintf(os.Stderr, "warning: remote policy %s has no checksum, integrity not verified\n", remote.URL)
	} else {
		if err := verifyChecksum(body, remote.Checksum); err != nil {
			return "", fmt.Errorf("verifying %s: %w", remote.URL, err)
		}
	}

	return string(body), nil
}

func isBlockedHost(host string) bool {
	hostname := host

	if strings.HasPrefix(hostname, "[") {
		if idx := strings.Index(hostname, "]"); idx != -1 {
			hostname = hostname[1:idx]
		}
	} else if idx := strings.LastIndex(hostname, ":"); idx != -1 {
		if strings.Count(hostname, ":") == 1 {
			hostname = hostname[:idx]
		}
	}

	hostname = strings.ToLower(hostname)

	if hostname == "localhost" {
		return true
	}

	ip := net.ParseIP(hostname)
	if ip == nil {
		ips, err := net.LookupIP(hostname)
		if err != nil || len(ips) == 0 {
			return false
		}
		ip = ips[0]
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// AWS/GCP/Azure metadata endpoints
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}

	return false
}

func verifyChecksum(data []byte, expected string) error {
	expected = strings.TrimPrefix(expected, "sha256:")

	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])

	if actual != expected {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, actual)
	}

	return nil
}

func policyNameFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	cleanPath := strings.TrimRight(u.Path, "/")
	name := path.Base(cleanPath)

	if name == "" || name == "." || name == "/" {
		return u.Host + ".rego"
	}

	if !strings.HasSuffix(name, ".rego") {
		return u.Host + ".rego"
	}

	return name
}
