package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// FetchRemotePolicies downloads policies from configured remote URLs.
func (c *Config) FetchRemotePolicies() (map[string]string, error) {
	policies := make(map[string]string)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: safeDialContext,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
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

func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %w", addr, err)
	}

	if isBlockedHostname(host) {
		return nil, fmt.Errorf("blocked hostname %q", host)
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup for %s: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", host)
	}

	var safeIPs []net.IP
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("blocked IP %s for host %s", ip, host)
		}
		safeIPs = append(safeIPs, ip)
	}

	var lastErr error
	dialer := &net.Dialer{}
	for _, ip := range safeIPs {
		target := net.JoinHostPort(ip.String(), port)
		conn, err := dialer.DialContext(ctx, network, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("failed to connect to %s: %w", host, lastErr)
}

const maxPolicySize = 10 * 1024 * 1024

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
		log.Printf("[regolint] warning: remote policy %s has no checksum, integrity not verified", remote.URL)
	} else {
		if err := verifyChecksum(body, remote.Checksum); err != nil {
			return "", fmt.Errorf("verifying %s: %w", remote.URL, err)
		}
	}

	return string(body), nil
}

func isBlockedHostname(hostname string) bool {
	return strings.EqualFold(hostname, "localhost")
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
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

	if isBlockedHostname(hostname) {
		return true
	}

	ip := net.ParseIP(hostname)
	if ip != nil {
		return isBlockedIP(ip)
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
