package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// infoHandler renders the detailed system info page
func infoHandler(w http.ResponseWriter, r *http.Request) {
	info := collectSysInfo()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "info.html", info)
}

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
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(data))
	}
	up := systemUptime()

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

	return sysInfo{
		Hostname:   host,
		OS:         runtime.GOOS + " " + runtime.GOARCH,
		Kernel:     kernel,
		Uptime:     up,
		Interfaces: ifs,
		Routes:     collectRoutes(),
		DNSServers: collectDNSServers(),
		Proxies:    collectProxies(),
	}
}

func collectRoutes() []string {
	if out, err := exec.Command("ip", "route", "show", "table", "main").Output(); err == nil {
		return strings.Split(strings.TrimSpace(string(out)), "\n")
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
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
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
	if env := os.Getenv("DNS_SERVERS"); env != "" {
		return strings.Split(env, ",")
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
