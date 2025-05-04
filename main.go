// NOC2GO – Swiss‑Army NOC Toolkit
// Copyright © 2025 Michael
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"
)

var (
	cfgPath    = flag.String("config", "noc2go.yaml", "path to YAML config")
	portFlag   = flag.Int("port", 0, "TCP port for HTTPS listener (>1024); 0 = use default or next free")
	password   = flag.String("password", "", "admin password (only used on first run)")
	privileged = flag.Bool("privileged", false, "enable raw-socket features (requires root/admin)")
)

const (
	defaultPort = 8443 // preferred default port
	certFile    = "noc2go.pem"
	keyFile     = "noc2go.key"
)

func main() {
	flag.Parse()

	// 1) Port bestimmen
	port := choosePort(*portFlag)

	// 2) Prüfen, ob Config existiert
	confExists := fileExists(*cfgPath)

	// 3) Falls keine Config vorhanden und kein Passwort übergeben, Random erzeugen
	if !confExists && *password == "" {
		*password = randomString(24)
	}

	// 4) Konfig laden oder neu anlegen
	cfg, err := loadOrInitConfig(*cfgPath, port, *password)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	// 5) Startup‑Banner
	fmt.Printf("[NOC2GO]   HTTPS  : https://localhost:%d\n", cfg.Server.Port)
	if !confExists {
		fmt.Printf("[NOC2GO]   LOGIN  : admin / %s\n", *password)
	} else {
		fmt.Printf("[NOC2GO]   LOGIN  : use credentials from %s\n", *cfgPath)
	}
	fmt.Printf("[NOC2GO]   MODE   : %s\n\n", ternary(*privileged, "privileged", "user"))

	// 6) TLS‑Keypair erzeugen, falls fehlt
	if !fileExists(certFile) || !fileExists(keyFile) {
		if err := generateSelfSigned(certFile, keyFile); err != nil {
			log.Fatalf("cannot create TLS keys: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin(cfg))
	mux.HandleFunc("/logout", handleLogout())
	mux.HandleFunc("/", rootHandler)

	handler := authMiddleware(mux, cfg)

	srv := &http.Server{
		Addr:      fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:   handler,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
}

// ---------------- util & helper ----------------

func choosePort(flagPort int) int {
	if flagPort > 0 && available(flagPort) {
		return flagPort
	}
	if available(defaultPort) {
		return defaultPort
	}
	free, err := freePort()
	if err != nil {
		log.Fatalf("cannot find free port: %v", err)
	}
	return free
}

func available(p int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<style>button{padding:6px 12px;border-radius:6px;border:none;background:#2563eb;color:#fff;cursor:pointer;}header{display:flex;justify-content:space-between;align-items:center;}body{font-family:sans-serif;margin:2rem;}</style>`)
	fmt.Fprint(w, `<header><h1>NOC2GO – It works!</h1><form action="/logout" method="post"><button>Logout</button></form></header>`)
	fmt.Fprintf(w, "<p>OS/Arch: %s %s</p>", runtime.GOOS, runtime.GOARCH)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

func generateSelfSigned(certOut, keyOut string) error {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "noc2go.local"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOutF, _ := os.Create(certOut)
	pem.Encode(certOutF, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOutF.Close()

	keyOutF, _ := os.Create(keyOut)
	pem.Encode(keyOutF, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOutF.Close()

	return nil
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
