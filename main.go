// NOC2GO – Swiss-Army NOC Toolkit
// Copyright © 2025 Michael
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
)

var (
	cfgPath    = flag.String("config", "noc2go.yaml", "path to YAML config")
	portFlag   = flag.Int("port", 0, "TCP port for HTTPS listener (>1024); 0 = use default or next free")
	password   = flag.String("password", "", "admin password (only used on first run)")
	privileged = flag.Bool("privileged", false, "enable raw-socket features (requires root/admin)")

	templates = template.Must(template.ParseGlob("templates/*.html"))
)

const (
	defaultPort = 8443
	certFile    = "noc2go.pem"
	keyFile     = "noc2go.key"
)

func main() {
	flag.Parse()

	port := choosePort(*portFlag)
	confExists := fileExists(*cfgPath)
	if !confExists && *password == "" {
		*password = randomString(24)
	}
	cfg, err := loadOrInitConfig(*cfgPath, port, *password)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	ip := firstNonLoopbackIP()
	fmt.Printf("[NOC2GO]   HTTPS  : https://%s:%d\n", ip, cfg.Server.Port)
	if !confExists {
		fmt.Printf("[NOC2GO]   LOGIN  : admin / %s\n", *password)
	} else {
		fmt.Printf("[NOC2GO]   LOGIN  : use credentials from %s\n", *cfgPath)
	}
	fmt.Printf("[NOC2GO]   MODE   : %s\n\n", ternary(*privileged, "privileged", "user"))

	if !fileExists(certFile) || !fileExists(keyFile) {
		if err := generateSelfSigned(certFile, keyFile); err != nil {
			log.Fatalf("cannot create TLS keys: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin(cfg))
	mux.HandleFunc("/logout", handleLogout())
	mux.HandleFunc("/passwd", handleChangePassword(cfg))
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/info", infoHandler)
	mux.HandleFunc("/dns", dnsPageHandler)
	mux.HandleFunc("/api/dns", apiDNSHandler)

	handler := authMiddleware(mux, cfg)

	srv := &http.Server{
		Addr:      fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:   handler,
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

// dnsPageHandler renders the DNS lookup page via template
func dnsPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "dns.html", nil)
}
