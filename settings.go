package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

type dnsRequest struct {
	Server string `json:"server"`
}

type dnsResponse struct {
	Success bool     `json:"success"`
	Error   string   `json:"error,omitempty"`
	Servers []string `json:"servers,omitempty"`
}

// settingsPageHandler renders GET /settings
func settingsPageHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		templates.ExecuteTemplate(w, "settings.html", cfg.DNS.CustomServers)
	}
}

// normalizeServer ensures host:port form, appending :53 if absent
func normalizeServer(input string) string {
	if !strings.Contains(input, ":") {
		return input + ":53"
	}
	parts := strings.Split(input, ":")
	host := strings.Join(parts[:len(parts)-1], ":")
	port := parts[len(parts)-1]
	if port == "" || port == "53" {
		return host + ":53"
	}
	return input
}

// apiAddDNSServerHandler handles POST /api/settings/dns/add
func apiAddDNSServerHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req dnsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		newSrv := normalizeServer(strings.TrimSpace(req.Server))
		for _, s := range cfg.DNS.CustomServers {
			if s == newSrv {
				json.NewEncoder(w).Encode(dnsResponse{Success: false, Error: "duplicate server"})
				return
			}
		}
		cfg.DNS.CustomServers = append(cfg.DNS.CustomServers, newSrv)
		if err := saveConfig(*cfgPath, cfg); err != nil {
			json.NewEncoder(w).Encode(dnsResponse{Success: false, Error: "failed to save"})
			return
		}
		json.NewEncoder(w).Encode(dnsResponse{Success: true, Servers: cfg.DNS.CustomServers})
	}
}

// apiRemoveDNSServerHandler handles POST /api/settings/dns/remove
func apiRemoveDNSServerHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req dnsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		toRemove := normalizeServer(strings.TrimSpace(req.Server))
		newList := []string{}
		found := false
		for _, s := range cfg.DNS.CustomServers {
			if s == toRemove {
				found = true
				continue
			}
			newList = append(newList, s)
		}
		if !found {
			json.NewEncoder(w).Encode(dnsResponse{Success: false, Error: "server not found"})
			return
		}
		cfg.DNS.CustomServers = newList
		if err := saveConfig(*cfgPath, cfg); err != nil {
			json.NewEncoder(w).Encode(dnsResponse{Success: false, Error: "failed to save"})
			return
		}
		json.NewEncoder(w).Encode(dnsResponse{Success: true, Servers: cfg.DNS.CustomServers})
	}
}
