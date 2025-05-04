// NOC2GO – Swiss‑Army NOC Toolkit
// Copyright © 2025 Michael
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ---------------- flags & const ----------------
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

// ---------------- main ----------------
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
	mux.HandleFunc("/passwd", handleChangePassword(cfg)) // <‑‑ diese Zeile neu
	mux.HandleFunc("/", rootHandler)

	handler := authMiddleware(mux, cfg)

	srv := &http.Server{
		Addr:      fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:   handler,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
}

// ---------------- system info helpers ----------------

type netIF struct {
	Name  string
	MAC   string
	Addrs []string
}

type sysInfo struct {
	Hostname   string
	OS         string
	Kernel     string
	Uptime     string
	Interfaces []netIF
	Routes     []string
	DNSServers []string
	Proxies    []string
}

func collectSysInfo() sysInfo {
	host, _ := os.Hostname()

	kernel := runtime.GOOS
	if data, err := ioutil.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(data))
	}

	up := systemUptime()

	// interfaces
	var ifs []netIF
	list, _ := net.Interfaces()
	for _, i := range list {
		var addrs []string
		addrList, _ := i.Addrs()
		for _, a := range addrList {
			addrs = append(addrs, a.String())
		}
		ifs = append(ifs, netIF{Name: i.Name, MAC: i.HardwareAddr.String(), Addrs: addrs})
	}

	routes := collectRoutes()
	dns := collectDNSServers()
	proxies := collectProxies()

	return sysInfo{
		Hostname:   host,
		OS:         runtime.GOOS + " " + runtime.GOARCH,
		Kernel:     kernel,
		Uptime:     up,
		Interfaces: ifs,
		Routes:     routes,
		DNSServers: dns,
		Proxies:    proxies,
	}
}

func collectRoutes() []string {
	if out, err := exec.Command("ip", "route", "show", "table", "main").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		return lines
	}
	if out, err := exec.Command("netstat", "-rn").Output(); err == nil {
		var result []string
		for _, l := range strings.Split(string(out), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "Kernel") || strings.HasPrefix(l, "Destination") {
				continue
			}
			result = append(result, l)
		}
		return result
	}
	return []string{"unavailable"}
}

func collectDNSServers() []string {
	if data, err := ioutil.ReadFile("/etc/resolv.conf"); err == nil {
		var servers []string
		for _, l := range strings.Split(string(data), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 && f[0] == "nameserver" {
				servers = append(servers, f[1])
			}
		}
		if len(servers) > 0 {
			return servers
		}
	}
	if servers := os.Getenv("DNS_SERVERS"); servers != "" {
		return strings.Split(servers, ",")
	}
	return []string{"unavailable"}
}

func collectProxies() []string {
	var p []string
	for _, key := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		if v := os.Getenv(key); v != "" {
			p = append(p, fmt.Sprintf("%s=%s", key, v))
		}
	}
	if len(p) == 0 {
		p = append(p, "none")
	}
	return p
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
	info := collectSysInfo()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)

	fmt.Fprint(bw, `<style>
    body{font-family:sans-serif;margin:2rem;max-width:1000px}
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;}
    button{padding:6px 12px;border:none;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer;}
    table{border-collapse:collapse;margin-top:1rem;width:100%;}
    td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top;}
    th{background:#f8f8f8;}
    h2{margin-top:2rem;}
    pre{background:#fafafa;border:1px solid #eee;padding:8px;overflow:auto;white-space:pre-wrap;}
    </style>`)

	fmt.Fprint(bw, `<header><h1>NOC2GO – System Info</h1>
    <div style="margin-left:auto;display:flex;gap:.5rem">
        <form action="/passwd" method="get"><button>Change&nbsp;Password</button></form>
        <form action="/logout" method="post"><button>Logout</button></form>
    </div></header>`)

	// Basic
	fmt.Fprintf(bw, `<table><tr><th>Hostname</th><td>%s</td></tr>`, info.Hostname)
	fmt.Fprintf(bw, `<tr><th>OS/Arch</th><td>%s</td></tr>`, info.OS)
	fmt.Fprintf(bw, `<tr><th>Kernel</th><td>%s</td></tr>`, info.Kernel)
	fmt.Fprintf(bw, `<tr><th>Uptime</th><td>%s</td></tr></table>`, info.Uptime)

	// Interfaces
	fmt.Fprint(bw, `<h2>Network Interfaces</h2><table><tr><th>Name</th><th>MAC</th><th>Addresses</th></tr>`)
	for _, i := range info.Interfaces {
		fmt.Fprintf(bw, `<tr><td>%s</td><td>%s</td><td>%s</td></tr>`, i.Name, i.MAC, strings.Join(i.Addrs, "<br>"))
	}
	fmt.Fprint(bw, `</table>`)

	// Routes
	fmt.Fprint(bw, `<h2>Routing Table</h2><pre>`+strings.Join(info.Routes, "\n")+`</pre>`)

	// DNS
	fmt.Fprintf(bw, `<h2>DNS Servers</h2><pre>%s</pre>`, strings.Join(info.DNSServers, "\n"))

	// Proxy
	fmt.Fprintf(bw, `<h2>Proxy Settings</h2><pre>%s</pre>`, strings.Join(info.Proxies, "\n"))

	bw.Flush()
	w.Write(buf.Bytes())
}

// ---------- helpers ----------

// randomString returns an alphanumeric string of length n.
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

// freePort asks the OS for a free TCP port (>1024) and returns it.
func freePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// fileExists reports whether the given path exists (regular file or dir).
func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// generateSelfSigned creates a PEM‑encoded cert/key pair valid for localhost.
func generateSelfSigned(certOut, keyOut string) error {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "noc2go.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	cf, _ := os.Create(certOut)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = cf.Close()

	kf, _ := os.Create(keyOut)
	_ = pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	_ = kf.Close()

	return nil
}

// ternary is a small helper that mimics a?b:c  (cond ? a : b).
func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// firstNonLoopbackIP returns the first active, non‑loopback IPv4 address.
// Falls nichts gefunden wird, kommt „localhost“ zurück.
func firstNonLoopbackIP() string {
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "localhost"
}

// ---------- end of main.go ----------
