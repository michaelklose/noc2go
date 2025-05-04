package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Serve the Ping page
func pingPageHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := struct {
			Privileged bool
			Targets    []string
		}{
			isPrivileged,
			cfg.Ping.Targets,
		}
		templates.ExecuteTemplate(w, "ping.html", data)
	}
}

// Save a target into config (deduped)
func apiSavePingTargetHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target string `json:"target"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		t := strings.TrimSpace(req.Target)
		for _, v := range cfg.Ping.Targets {
			if v == t {
				// already present
				json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "targets": cfg.Ping.Targets})
				return
			}
		}
		cfg.Ping.Targets = append(cfg.Ping.Targets, t)
		saveConfig(*cfgPath, cfg)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "targets": cfg.Ping.Targets})
	}
}

// Streamed ping via Server-Sent Events
func apiPingHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := q.Get("target")
	family := q.Get("family") // "ipv4"/"ipv6"/"auto"
	count := q.Get("count")
	size := q.Get("size")
	interval := q.Get("interval")
	ttl := q.Get("ttl")
	df := q.Get("df") // "true"/"false"

	// Resolve to an IP
	var ipStr string
	if parsed := net.ParseIP(target); parsed != nil {
		ipStr = parsed.String()
	} else {
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			http.Error(w, "cannot resolve target", http.StatusBadRequest)
			return
		}
		// pick per family
		for _, ip := range ips {
			if family == "ipv6" && ip.To4() == nil {
				ipStr = ip.String()
				break
			}
			if family != "ipv6" && ip.To4() != nil {
				ipStr = ip.String()
				break
			}
		}
		if ipStr == "" {
			ipStr = ips[0].String()
		}
	}

	// Build ping command args
	args := []string{}
	goos := runtime.GOOS
	// force v4/v6 flag
	if goos == "linux" || goos == "darwin" || goos == "windows" {
		if family == "ipv6" {
			args = append(args, "-6")
		} else {
			args = append(args, "-4")
		}
	}
	// count
	if count != "" {
		if goos == "windows" {
			args = append(args, "-n", count)
		} else {
			args = append(args, "-c", count)
		}
	}
	// size
	if size != "" {
		if goos == "windows" {
			args = append(args, "-l", size)
		} else {
			args = append(args, "-s", size)
		}
	}
	// interval (not on Windows)
	if interval != "" && goos != "windows" {
		args = append(args, "-i", interval)
	}
	// ttl
	if ttl != "" {
		if goos == "windows" {
			args = append(args, "-i", ttl) // Windows uses -i for TTL
		} else if goos == "darwin" {
			args = append(args, "-m", ttl)
		} else {
			args = append(args, "-t", ttl)
		}
	}
	// don't fragment (Linux only)
	if df == "true" && goos == "linux" {
		args = append(args, "-M", "dont")
	}
	// timestamp (Linux & Darwin)
	if goos != "windows" {
		args = append(args, "-D")
	}

	args = append(args, ipStr)
	cmd := exec.Command("ping", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, "failed to start ping", http.StatusInternalServerError)
		return
	}
	if err := cmd.Start(); err != nil {
		http.Error(w, "failed to start ping", http.StatusInternalServerError)
		return
	}

	// SSE setup
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	scanner := bufio.NewScanner(stdout)
	lineRE := regexp.MustCompile(`icmp_seq=(\d+)\s+ttl=(\d+)\s+time=([\d\.]+)`)
	var summaryLines []string

	for scanner.Scan() {
		line := scanner.Text()
		if m := lineRE.FindStringSubmatch(line); m != nil {
			seq, _ := strconv.Atoi(m[1])
			ttlv, _ := strconv.Atoi(m[2])
			timeVal, _ := strconv.ParseFloat(m[3], 64)
			ts := time.Now().Format(time.RFC3339Nano)
			fmt.Fprintf(w,
				"event: reply\ndata: {\"seq\":%d,\"ttl\":%d,\"time\":%f,\"timestamp\":\"%s\",\"ip\":\"%s\"}\n\n",
				seq, ttlv, timeVal, ts, ipStr,
			)
			flusher.Flush()
		} else {
			// accumulate for summary parsing
			summaryLines = append(summaryLines, line)
		}
	}
	cmd.Wait()

	// parse summary
	var sent, recv int
	var loss, min, avg, max float64
	for _, l := range summaryLines {
		if strings.Contains(l, "packets transmitted") {
			parts := strings.Split(l, ",")
			if len(parts) >= 3 {
				sent, _ = strconv.Atoi(strings.Fields(parts[0])[0])
				recv, _ = strconv.Atoi(strings.Fields(parts[1])[0])
				lossStr := strings.TrimSuffix(strings.TrimSpace(parts[2]), "% packet loss")
				loss, _ = strconv.ParseFloat(lossStr, 64)
			}
		}
		if strings.Contains(l, "min/avg") {
			// e.g. rtt min/avg/max/mdev = 0.035/0.041/0.049/0.004 ms
			parts := strings.SplitN(l, "=", 2)
			if len(parts) == 2 {
				vals := strings.Fields(parts[1])
				p := strings.Split(vals[0], "/")
				if len(p) >= 3 {
					min, _ = strconv.ParseFloat(p[0], 64)
					avg, _ = strconv.ParseFloat(p[1], 64)
					max, _ = strconv.ParseFloat(p[2], 64)
				}
			}
		}
	}

	// send summary event
	fmt.Fprintf(w,
		"event: summary\ndata: {\"sent\":%d,\"recv\":%d,\"loss\":%f,\"min\":%f,\"avg\":%f,\"max\":%f}\n\n",
		sent, recv, loss, min, avg, max,
	)
	flusher.Flush()
}
