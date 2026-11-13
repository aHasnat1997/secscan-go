package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Suppression defines a rule to whitelist or silence a specific finding.
type Suppression struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Config represents persistent security configuration and whitelists.
type Config struct {
	Suppress        []Suppression `json:"suppress"`
	AllowedPorts    []int         `json:"allowed_ports"`
	ClamPaths       []string      `json:"clamav_paths"`
	IgnoreToolWarns []string      `json:"ignore_tool_warnings_regex"`
}

// DefaultConfig returns safe baseline configuration values.
func DefaultConfig() Config {
	return Config{
		Suppress: []Suppression{
			{ID: "ACC-DORMANT-bin", Reason: "system service account"},
			{ID: "ACC-DORMANT-daemon", Reason: "system service account"},
			{ID: "ACC-DORMANT-mail", Reason: "system service account"},
			{ID: "ACC-DORMANT-ftp", Reason: "system service account"},
			{ID: "ACC-DORMANT-nobody", Reason: "system service account"},
			{ID: "ACC-DORMANT-dbus", Reason: "system service account"},
			{ID: "ACC-DORMANT-systemd-*", Reason: "systemd service accounts"},
		},
		AllowedPorts: []int{22},
		ClamPaths:    []string{"/home", "/tmp", "/var/tmp"},
		IgnoreToolWarns: []string{
			`(?i)cannot find (rkhunter|lynis) data file`,
			`(?i)hash func not found`,
		},
	}
}

// Load loads configuration from the specified file path, falling back to standard search paths.
func Load(path string) (*Config, error) {
	if path == "" {
		candidates := []string{
			"/etc/secscan/config.json",
			filepath.Join(os.Getenv("HOME"), ".config/secscan/config.json"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}

	cfg := DefaultConfig()
	if path == "" {
		return &cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &cfg, nil
		}
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	return &cfg, nil
}

// IsSuppressed checks whether a finding ID is suppressed by explicit ID or wildcard pattern.
func (c *Config) IsSuppressed(id string) string {
	if c == nil {
		return ""
	}
	for _, s := range c.Suppress {
		if s.ID == id {
			return s.Reason
		}
		if strings.HasSuffix(s.ID, "*") && strings.HasPrefix(id, strings.TrimSuffix(s.ID, "*")) {
			return s.Reason
		}
	}
	return ""
}

// WriteExample writes a template configuration file to disk.
func WriteExample(dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	cfg := DefaultConfig()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dest, append(data, '\n'), 0o644)
}

