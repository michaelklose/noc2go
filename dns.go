package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"strconv"

	"github.com/miekg/dns"
)

const (
	dnsTimeout = 5 * time.Second
	cacheTTL   = 60 * time.Second
)

var (
	dnsCache   = make(map[string]cacheEntry)
	cacheMutex sync.Mutex
)

type cacheEntry struct {
	timestamp time.Time
	records   interface{}
	err       error
}

// page data for template
type dnsPageData struct {
	CustomServers []string
}

// dnsPageHandler renders GET /dns
func dnsPageHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := dnsPageData{
			CustomServers: cfg.DNS.CustomServers,
		}
		templates.ExecuteTemplate(w, "dns.html", data)
	}
}

// apiDNSHandler handles GET /api/dns?name=...&type=...&server=...
func apiDNSHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	typ := strings.ToUpper(r.URL.Query().Get("type"))
	serverParam := r.URL.Query().Get("server")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if name == "" || typ == "" {
		fmt.Fprint(w, `{"error":"name and type are required"}`)
		return
	}

	records, serverUsed, err := lookupDNS(name, typ, serverParam)
	if err != nil {
		fmt.Fprintf(w, `{"error":%q}`, err.Error())
		return
	}
	resp := map[string]interface{}{
		"server":  serverUsed,
		"records": records,
	}
	data, _ := json.Marshal(resp)
	fmt.Fprint(w, string(data))
}

// lookupDNS does the actual query (with caching and timeout, override via serverParam)
func lookupDNS(name, typ, override string) (interface{}, string, error) {
	lookupName := name
	if typ == "PTR" {
		if ip := net.ParseIP(name); ip != nil {
			lookupName = reverseIP(ip)
		} else {
			lower := strings.ToLower(name)
			if !(strings.HasSuffix(lower, ".in-addr.arpa") || strings.HasSuffix(lower, ".ip6.arpa")) {
				return nil, "", fmt.Errorf("invalid input for PTR lookup: must be IP or reverse-ARPA domain")
			}
		}
	}

	// choose which DNS server to use
	var serverUsed string
	if override != "" && override != "system" {
		serverUsed = override
	} else {
		sys := collectDNSServers()
		if len(sys) > 0 && sys[0] != "unavailable" {
			serverUsed = net.JoinHostPort(sys[0], "53")
		} else {
			serverUsed = "8.8.8.8:53"
		}
	}
	// ensure host:port
	if !strings.Contains(serverUsed, ":") {
		serverUsed = net.JoinHostPort(serverUsed, "53")
	}

	key := strings.ToLower(lookupName + "|" + typ + "|" + serverUsed)
	cacheMutex.Lock()
	if e, ok := dnsCache[key]; ok && time.Since(e.timestamp) < cacheTTL {
		cacheMutex.Unlock()
		return e.records, serverUsed, e.err
	}
	cacheMutex.Unlock()

	client := new(dns.Client)
	client.Timeout = dnsTimeout
	msg := new(dns.Msg)
	qtype, ok := map[string]uint16{
		"A":    dns.TypeA,
		"AAAA": dns.TypeAAAA,
		"MX":   dns.TypeMX,
		"NS":   dns.TypeNS,
		"PTR":  dns.TypePTR,
		"TXT":  dns.TypeTXT,
		"SRV":  dns.TypeSRV,
	}[typ]
	if !ok {
		return nil, serverUsed, fmt.Errorf("unsupported record type %q", typ)
	}
	msg.SetQuestion(dns.Fqdn(lookupName), qtype)

	resp, _, err := client.Exchange(msg, serverUsed)
	if err != nil {
		cacheMutex.Lock()
		dnsCache[key] = cacheEntry{time.Now(), nil, err}
		cacheMutex.Unlock()
		return nil, serverUsed, err
	}
	if resp.Rcode == dns.RcodeNameError {
		err = fmt.Errorf("NXDOMAIN")
		cacheMutex.Lock()
		dnsCache[key] = cacheEntry{time.Now(), nil, err}
		cacheMutex.Unlock()
		return nil, serverUsed, err
	}

	var out interface{}
	switch qtype {
	case dns.TypeA:
		var arr []map[string]string
		for _, ans := range resp.Answer {
			if rr, ok := ans.(*dns.A); ok {
				arr = append(arr, map[string]string{"address": rr.A.String()})
			}
		}
		out = arr
	case dns.TypeAAAA:
		var arr []map[string]string
		for _, ans := range resp.Answer {
			if rr, ok := ans.(*dns.AAAA); ok {
				arr = append(arr, map[string]string{"address": rr.AAAA.String()})
			}
		}
		out = arr
	case dns.TypeMX:
		var arr []map[string]interface{}
		for _, ans := range resp.Answer {
			if rr, ok := ans.(*dns.MX); ok {
				arr = append(arr, map[string]interface{}{"host": rr.Mx, "priority": rr.Preference})
			}
		}
		out = arr
	case dns.TypeNS:
		var arr []map[string]string
		for _, ans := range resp.Answer {
			if rr, ok := ans.(*dns.NS); ok {
				arr = append(arr, map[string]string{"host": rr.Ns})
			}
		}
		out = arr
	case dns.TypePTR:
		var arr []map[string]string
		for _, ans := range resp.Answer {
			if rr, ok := ans.(*dns.PTR); ok {
				arr = append(arr, map[string]string{"host": rr.Ptr})
			}
		}
		out = arr
	case dns.TypeTXT:
		var arr []map[string]string
		for _, ans := range resp.Answer {
			if rr, ok := ans.(*dns.TXT); ok {
				arr = append(arr, map[string]string{"text": strings.Join(rr.Txt, "")})
			}
		}
		out = arr
	case dns.TypeSRV:
		var arr []map[string]interface{}
		for _, ans := range resp.Answer {
			if rr, ok := ans.(*dns.SRV); ok {
				arr = append(arr, map[string]interface{}{
					"target":   rr.Target,
					"port":     rr.Port,
					"priority": rr.Priority,
					"weight":   rr.Weight,
				})
			}
		}
		out = arr
	}

	cacheMutex.Lock()
	dnsCache[key] = cacheEntry{time.Now(), out, nil}
	cacheMutex.Unlock()
	return out, serverUsed, nil
}

// reverseIP builds the in-addr or ip6.arpa name for an IP
func reverseIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		parts := make([]string, 0, 4)
		for i := len(ip4) - 1; i >= 0; i-- {
			parts = append(parts, strconv.Itoa(int(ip4[i])))
		}
		return strings.Join(parts, ".") + ".in-addr.arpa"
	}
	ip16 := ip.To16()
	var nibbles []string
	for i := len(ip16) - 1; i >= 0; i-- {
		b := ip16[i]
		// low nibble
		nibbles = append(nibbles, fmt.Sprintf("%x", b&0xF))
		// high nibble
		nibbles = append(nibbles, fmt.Sprintf("%x", b>>4))
	}
	return strings.Join(nibbles, ".") + ".ip6.arpa"
}
