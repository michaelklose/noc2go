// NOC2GO – Swiss-Army NOC Toolkit
// Copyright © 2025 Michael
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	cfgPath    = flag.String("config", "noc2go.yaml", "path to YAML config")
	portFlag   = flag.Int("port", 0, "TCP port for HTTPS listener (>1024); 0 = use default or next free")
	password   = flag.String("password", "", "admin password (only used on first run)")
	privileged = flag.Bool("privileged", false, "enable raw-socket features (requires root/admin)")

	templates = template.Must(template.ParseGlob("templates/*.html"))

	// new global for ping privilege
	isPrivileged bool
)

// multiFlag allows repeated --dns-server flags
type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

var dnsServersFlag multiFlag

const (
	defaultPort = 8443
	certFile    = "noc2go.pem"
	keyFile     = "noc2go.key"
)

type filterWriter struct {
	dst io.Writer
}

func (fw *filterWriter) Write(p []byte) (n int, err error) {
	if bytes.Contains(p, []byte("tls: unknown certificate")) {
		// swallow these
		return len(p), nil
	}
	return fw.dst.Write(p)
}

func main() {
	flag.Var(&dnsServersFlag, "dns-server", "DNS server to use (can specify multiple times, format IP or IP[:port])")
	flag.Parse()
	isPrivileged = *privileged

	port := choosePort(*portFlag)
	confExists := fileExists(*cfgPath)
	if !confExists && *password == "" {
		*password = randomString(24)
	}
	cfg, err := loadOrInitConfig(*cfgPath, port, *password)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	// merge any CLI --dns-server flags
	if len(dnsServersFlag) > 0 {
		existing53 := make(map[string]bool)
		for _, srv := range cfg.DNS.CustomServers {
			if !strings.Contains(srv, ":") {
				existing53[srv+":53"] = true
			} else {
				parts := strings.Split(srv, ":")
				host := strings.Join(parts[:len(parts)-1], ":")
				if parts[len(parts)-1] == "53" {
					existing53[host+":53"] = true
				}
			}
		}
		cli53Seen := make(map[string]bool)
		cliNon53Seen := make(map[string]bool)
		var toAdd []string
		for _, srv := range dnsServersFlag {
			if !strings.Contains(srv, ":") {
				norm := srv + ":53"
				if existing53[norm] || cli53Seen[norm] {
					continue
				}
				cli53Seen[norm] = true
				toAdd = append(toAdd, norm)
			} else {
				parts := strings.Split(srv, ":")
				host, port := strings.Join(parts[:len(parts)-1], ":"), parts[len(parts)-1]
				if port == "53" {
					norm := host + ":53"
					if existing53[norm] || cli53Seen[norm] {
						continue
					}
					cli53Seen[norm] = true
					toAdd = append(toAdd, norm)
				} else {
					if cliNon53Seen[srv] {
						continue
					}
					cliNon53Seen[srv] = true
					toAdd = append(toAdd, srv)
				}
			}
		}
		cfg.DNS.CustomServers = append(cfg.DNS.CustomServers, toAdd...)
		if err := saveConfig(*cfgPath, cfg); err != nil {
			log.Fatalf("cannot save config: %v", err)
		}
	}

	ip := firstNonLoopbackIP()
	fmt.Printf("[NOC2GO]   HTTPS  : https://%s:%d\n", ip, cfg.Server.Port)
	if !confExists {
		fmt.Printf("[NOC2GO]   LOGIN  : admin / %s\n", *password)
	} else {
		fmt.Printf("[NOC2GO]   LOGIN  : use credentials from %s\n", *cfgPath)
	}
	// fmt.Printf("[NOC2GO]   MODE   : %s\n\n", ternary(isPrivileged, "privileged", "user"))

	if !fileExists(certFile) || !fileExists(keyFile) {
		if err := generateSelfSigned(certFile, keyFile); err != nil {
			log.Fatalf("cannot create TLS keys: %v", err)
		}
	}

	// HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin(cfg))
	mux.HandleFunc("/logout", handleLogout())
	mux.HandleFunc("/passwd", handleChangePassword(cfg))
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/info", infoHandler)
	mux.HandleFunc("/dns", dnsPageHandler(cfg))
	mux.HandleFunc("/api/dns", apiDNSHandler)

	// settings
	mux.HandleFunc("/settings", settingsPageHandler(cfg))
	mux.HandleFunc("/api/settings/dns/add", apiAddDNSServerHandler(cfg))
	mux.HandleFunc("/api/settings/dns/remove", apiRemoveDNSServerHandler(cfg))
	mux.HandleFunc("/api/settings/ping/add", apiAddPingTargetHandler(cfg))
	mux.HandleFunc("/api/settings/ping/remove", apiRemovePingTargetHandler(cfg))

	// ping
	mux.HandleFunc("/ping", pingPageHandler(cfg))
	mux.HandleFunc("/api/ping", apiPingHandler)

	handler := authMiddleware(mux, cfg)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: handler,
		ErrorLog: log.New(
			&filterWriter{dst: os.Stderr},
			"", log.LstdFlags,
		),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
}

// rootHandler shows the main dashboard via template
func rootHandler(w http.ResponseWriter, r *http.Request) {
	info := collectSysInfo()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "index.html", info)
}
