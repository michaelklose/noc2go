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

// Serve Ping page
func pingPageHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := struct {
			Privileged bool
			Targets    []string
		}{isPrivileged, cfg.Ping.Targets}
		templates.ExecuteTemplate(w, "ping.html", data)
	}
}

// Streamed ping via SSE
func apiPingHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := q.Get("target")
	family := q.Get("family")
	count := q.Get("count")
	size := q.Get("size")
	interval := q.Get("interval")
	ttl := q.Get("ttl")
	df := q.Get("df")

	// Resolve to an IP
	var ipStr string
	if p := net.ParseIP(target); p != nil {
		ipStr = p.String()
	} else {
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			http.Error(w, "cannot resolve target", http.StatusBadRequest)
			return
		}
		for _, ip := range ips {
			if family == "ipv6" && ip.To4() == nil ||
				family != "ipv6" && ip.To4() != nil {
				ipStr = ip.String()
				break
			}
		}
		if ipStr == "" {
			ipStr = ips[0].String()
		}
	}

	// Build ping command
	args := []string{}
	goos := runtime.GOOS
	if goos == "windows" || goos == "linux" || goos == "darwin" {
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
		switch goos {
		case "windows":
			args = append(args, "-i", ttl)
		case "darwin":
			args = append(args, "-m", ttl)
		default:
			args = append(args, "-t", ttl)
		}
	}
	if df == "true" && goos == "linux" {
		args = append(args, "-M", "dont")
	}
	if goos != "windows" {
		args = append(args, "-D")
		args = append(args, "-O")
	}
	args = append(args, ipStr)

	cmd := exec.Command("ping", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
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

	// Compile regexes
	var okRE, unreachRE, timeoutRE, failRE, pktRE, rttRE *regexp.Regexp
	if goos == "windows" {
		okRE = regexp.MustCompile(`Reply from [^:]+: bytes=\d+\s+time[=<]?(\d+)?ms\s+TTL=(\d+)`)
		unreachRE = regexp.MustCompile(`Reply from [^:]+: Destination (?:host|net) unreachable\.`)
		timeoutRE = regexp.MustCompile(`Request timed out\.`)
		failRE = regexp.MustCompile(`General failure\.`)
		pktRE = regexp.MustCompile(`Packets: Sent = (\d+), Received = (\d+), Lost = (\d+) \((\d+)% loss\)`)
		rttRE = regexp.MustCompile(`Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms`)
	} else {
		// Linux & macOS
		okRE = regexp.MustCompile(`icmp_seq=(\d+)\s+ttl=(\d+)\s+time=([\d\.]+)`)
		unreachRE = regexp.MustCompile(`From [^ ]+ icmp_seq=(\d+) Destination (?:Host|Net) Unreachable`)
		timeoutRE = regexp.MustCompile(`no answer yet for icmp_seq=(\d+)`)
	}

	scanner := bufio.NewScanner(stdout)
	var summaryLines []string

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		// Successful reply
		case okRE.MatchString(line):
			m := okRE.FindStringSubmatch(line)
			var seq, ttlVal int
			var timeMs float64
			if goos == "windows" {
				seq = len(summaryLines) + 1
				ttlVal, _ = strconv.Atoi(m[2])
				timeMs, _ = strconv.ParseFloat(m[1], 64)
			} else {
				seq, _ = strconv.Atoi(m[1])
				ttlVal, _ = strconv.Atoi(m[2])
				timeMs, _ = strconv.ParseFloat(m[3], 64)
			}
			sendReply(w, flusher, seq, ttlVal, timeMs, ipStr, "received")

		// Linux destination unreachable
		case unreachRE != nil && unreachRE.MatchString(line):
			m := unreachRE.FindStringSubmatch(line)
			seq, _ := strconv.Atoi(m[1])
			sendReply(w, flusher, seq, 0, -1, ipStr, "destination unreachable")

		// Linux timeout
		case timeoutRE != nil && timeoutRE.MatchString(line):
			m := timeoutRE.FindStringSubmatch(line)
			seq, _ := strconv.Atoi(m[1])
			sendReply(w, flusher, seq, 0, -1, ipStr, "timeout")

		// Windows general failure
		case failRE != nil && failRE.MatchString(line):
			seq := len(summaryLines) + 1
			sendReply(w, flusher, seq, 0, -1, ipStr, "failure")

		default:
			summaryLines = append(summaryLines, line)
		}
	}
	_ = cmd.Wait()

	// Parse summary
	var sent, recv int
	var loss, min, avg, max float64

	if goos == "windows" {
		for _, l := range summaryLines {
			if m := pktRE.FindStringSubmatch(l); m != nil {
				sent, _ = strconv.Atoi(m[1])
				recv, _ = strconv.Atoi(m[2])
				loss, _ = strconv.ParseFloat(m[4], 64)
			} else if m := rttRE.FindStringSubmatch(l); m != nil {
				min, _ = strconv.ParseFloat(m[1], 64)
				max, _ = strconv.ParseFloat(m[2], 64)
				avg, _ = strconv.ParseFloat(m[3], 64)
			}
		}
	} else {
		for _, l := range summaryLines {
			if strings.Contains(l, "packets transmitted") {
				parts := strings.Split(l, ",")
				sent, _ = strconv.Atoi(strings.Fields(parts[0])[0])
				recv, _ = strconv.Atoi(strings.Fields(parts[1])[0])
				lossStr := strings.TrimSuffix(strings.TrimSpace(parts[2]), "% packet loss")
				loss, _ = strconv.ParseFloat(lossStr, 64)
			}
		}
	}

	fmt.Fprintf(w,
		"event: summary\n"+
			"data: {\"sent\":%d,\"recv\":%d,\"loss\":%f,\"min\":%f,\"avg\":%f,\"max\":%f}\n\n",
		sent, recv, loss, min, avg, max,
	)
	flusher.Flush()
}

// Helper emits reply events with a status field
func sendReply(w http.ResponseWriter, f http.Flusher, seq, ttl int, t float64, ip, status string) {
	ts := time.Now().Format(time.RFC3339Nano)
	fmt.Fprintf(w,
		"event: reply\n"+
			"data: {\"seq\":%d,\"ttl\":%d,\"time\":%f,\"status\":\"%s\",\"timestamp\":\"%s\",\"ip\":\"%s\"}\n\n",
		seq, ttl, t, status, ts, ip,
	)
	f.Flush()
}
