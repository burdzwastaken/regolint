package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FetchRemotePolicies fetches all remote policies and returns their contents.
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

	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("unsupported URL scheme %q: only http/https allowed", u.Scheme)
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

	if remote.Checksum != "" {
		if err := verifyChecksum(body, remote.Checksum); err != nil {
			return "", fmt.Errorf("verifying %s: %w", remote.URL, err)
		}
	}

	return string(body), nil
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

	parts := strings.Split(u.Path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}

	return u.Host + ".rego"
}
