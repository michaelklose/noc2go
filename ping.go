package main

import (
	"bufio"
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

// Streamed ping via Server‑Sent Events
func apiPingHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := q.Get("target")
	family := q.Get("family") // "ipv4"/"ipv6"/"auto"
	count := q.Get("count")
	size := q.Get("size")
	interval := q.Get("interval")
	ttl := q.Get("ttl")
	df := q.Get("df") // "true"/"false"

	// ---------- resolve target ----------
	var ipStr string
	if parsed := net.ParseIP(target); parsed != nil {
		ipStr = parsed.String()
	} else {
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			http.Error(w, "cannot resolve target", http.StatusBadRequest)
			return
		}
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

	// ---------- build ping command ----------
	args := []string{}
	goos := runtime.GOOS
	if goos == "linux" || goos == "darwin" || goos == "windows" {
		if family == "ipv6" {
			args = append(args, "-6")
		} else {
			args = append(args, "-4")
		}
	}
	if count != "" {
		if goos == "windows" {
			args = append(args, "-n", count)
		} else {
			args = append(args, "-c", count)
		}
	}
	if size != "" {
		if goos == "windows" {
			args = append(args, "-l", size)
		} else {
			args = append(args, "-s", size)
		}
	}
	if interval != "" && goos != "windows" {
		args = append(args, "-i", interval)
	}
	if ttl != "" {
		if goos == "windows" {
			args = append(args, "-i", ttl)
		} else if goos == "darwin" {
			args = append(args, "-m", ttl)
		} else {
			args = append(args, "-t", ttl)
		}
	}
	if df == "true" && goos == "linux" {
		args = append(args, "-M", "dont")
	}
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

	// ---------- SSE headers ----------
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// ---------- regexes ----------
	var replyRE, pktSummaryRE, rttSummaryRE *regexp.Regexp
	if goos == "windows" {
		replyRE = regexp.MustCompile(`Reply from [^:]+: bytes=\d+\s+time[=<]([0-9]+)?ms\s+TTL=(\d+)`)
		pktSummaryRE = regexp.MustCompile(`Packets: Sent = (\d+), Received = (\d+), Lost = (\d+) \((\d+)% loss\)`)
		rttSummaryRE = regexp.MustCompile(`Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms`)
	} else {
		replyRE = regexp.MustCompile(`icmp_seq=(\d+)\s+ttl=(\d+)\s+time=([\d\.]+)`)
	}

	// ---------- stream output ----------
	scanner := bufio.NewScanner(stdout)
	var summaryLines []string
	seqCounter := 0

	for scanner.Scan() {
		line := scanner.Text()
		if m := replyRE.FindStringSubmatch(line); m != nil {
			if goos == "windows" {
				seqCounter++
				ttlVal, _ := strconv.Atoi(m[2])
				timeMs := 0.0
				if m[1] != "" {
					timeMs, _ = strconv.ParseFloat(m[1], 64)
				}
				ts := time.Now().Format(time.RFC3339Nano)
				fmt.Fprintf(w,
					"event: reply\ndata: {\"seq\":%d,\"ttl\":%d,\"time\":%f,\"timestamp\":\"%s\",\"ip\":\"%s\"}\n\n",
					seqCounter, ttlVal, timeMs, ts, ipStr,
				)
			} else {
				seq, _ := strconv.Atoi(m[1])
				ttlVal, _ := strconv.Atoi(m[2])
				timeMs, _ := strconv.ParseFloat(m[3], 64)
				ts := time.Now().Format(time.RFC3339Nano)
				fmt.Fprintf(w,
					"event: reply\ndata: {\"seq\":%d,\"ttl\":%d,\"time\":%f,\"timestamp\":\"%s\",\"ip\":\"%s\"}\n\n",
					seq, ttlVal, timeMs, ts, ipStr,
				)
			}
			flusher.Flush()
		} else {
			summaryLines = append(summaryLines, line)
		}
	}
	_ = cmd.Wait()

	// ---------- parse summary ----------
	var sent, recv int
	var loss, min, avg, max float64

	if goos == "windows" {
		for _, l := range summaryLines {
			if m := pktSummaryRE.FindStringSubmatch(l); m != nil {
				sent, _ = strconv.Atoi(m[1])
				recv, _ = strconv.Atoi(m[2])
				loss, _ = strconv.ParseFloat(m[4], 64)
			} else if m := rttSummaryRE.FindStringSubmatch(l); m != nil {
				min, _ = strconv.ParseFloat(m[1], 64)
				max, _ = strconv.ParseFloat(m[2], 64)
				avg, _ = strconv.ParseFloat(m[3], 64)
			}
		}
	} else {
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
	}

	// ---------- send summary ----------
	fmt.Fprintf(w,
		"event: summary\ndata: {\"sent\":%d,\"recv\":%d,\"loss\":%f,\"min\":%f,\"avg\":%f,\"max\":%f}\n\n",
		sent, recv, loss, min, avg, max,
	)
	flusher.Flush()
}
