package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

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

// apiDNSHandler handles GET /api/dns?name=...&type=...
func apiDNSHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	typ := strings.ToUpper(r.URL.Query().Get("type"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if name == "" || typ == "" {
		fmt.Fprint(w, `{"error":"name and type are required"}`)
		return
	}

	records, err := lookupDNS(name, typ)
	if err != nil {
		fmt.Fprintf(w, `{"error":%q}`, err.Error())
		return
	}
	fmt.Fprint(w, `{"records":`)
	data, _ := json.Marshal(records)
	w.Write(data)
	fmt.Fprint(w, `}`)
}

// lookupDNS does the actual query (with caching and timeout)
func lookupDNS(name, typ string) (interface{}, error) {
	key := strings.ToLower(name + "|" + typ)
	cacheMutex.Lock()
	if e, ok := dnsCache[key]; ok && time.Since(e.timestamp) < cacheTTL {
		cacheMutex.Unlock()
		return e.records, e.err
	}
	cacheMutex.Unlock()

	// choose DNS server (fallback to Google Public DNS)
	servers := collectDNSServers()
	server := "8.8.8.8:53"
	if len(servers) > 0 && servers[0] != "unavailable" {
		server = net.JoinHostPort(servers[0], "53")
	}

	client := new(dns.Client)
	client.Timeout = dnsTimeout
	msg := new(dns.Msg)
	qtype, ok := map[string]uint16{
		"A": dns.TypeA, "AAAA": dns.TypeAAAA, "MX": dns.TypeMX,
		"NS": dns.TypeNS, "PTR": dns.TypePTR, "TXT": dns.TypeTXT, "SRV": dns.TypeSRV,
	}[typ]
	if !ok {
		return nil, fmt.Errorf("unsupported record type %q", typ)
	}
	msg.SetQuestion(dns.Fqdn(name), qtype)

	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		cacheMutex.Lock()
		dnsCache[key] = cacheEntry{time.Now(), nil, err}
		cacheMutex.Unlock()
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		err = fmt.Errorf("NXDOMAIN")
		cacheMutex.Lock()
		dnsCache[key] = cacheEntry{time.Now(), nil, err}
		cacheMutex.Unlock()
		return nil, err
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
	return out, nil
}
