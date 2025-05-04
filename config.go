package main

import (
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Role string

const (
	Admin Role = "admin"
	User  Role = "user"
)

type UserEntry struct {
	Name     string `yaml:"name"`
	Role     Role   `yaml:"role"`
	PwHash   string `yaml:"pw_hash"`
	PwOneUse bool   `yaml:"pw_oneuse,omitempty"`
	Expires  string `yaml:"expires,omitempty"` // RFC3339, optional
}

type Config struct {
	Server struct {
		Port int    `yaml:"port"`
		Key  string `yaml:"https_key"`
	} `yaml:"server"`
	Auth struct {
		Users []UserEntry `yaml:"users"`
	} `yaml:"auth"`
	Tools struct {
		AllowPrivileged bool `yaml:"allow_privileged"`
	} `yaml:"tools"`
	DNS struct {
		CustomServers []string `yaml:"custom_servers"`
	} `yaml:"dns,omitempty"`
}

func defaultConfig(port int, pw string) *Config {
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	cfg := &Config{}
	cfg.Server.Port = port
	cfg.Server.Key = certFile
	cfg.Auth.Users = []UserEntry{
		{Name: "admin", Role: Admin, PwHash: string(hash)},
	}
	return cfg
}

func loadOrInitConfig(path string, port int, pw string) (*Config, error) {
	if _, err := os.Stat(path); err == nil {
		f, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var c Config
		if err := yaml.Unmarshal(f, &c); err != nil {
			return nil, err
		}
		return &c, nil
	}

	c := defaultConfig(port, pw)
	if err := saveConfig(path, c); err != nil {
		return nil, err
	}
	return c, nil
}

func saveConfig(path string, cfg *Config) error {
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0o750)
	out, _ := yaml.Marshal(cfg)
	return os.WriteFile(path, out, 0o600)
}
