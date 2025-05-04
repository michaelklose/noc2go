//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// systemUptime liefert die OS‑Uptime als „4d3h12m“-String unter Unix / Linux.
func systemUptime() string {
	// Linux: /proc/uptime  -> "12345.67 ..."
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if secs, err := strconv.ParseFloat(fields[0], 64); err == nil {
				d := time.Duration(secs) * time.Second
				return fmtDuration(d)
			}
		}
	}
	// Fallback
	return "unknown"
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	mins := d / time.Minute
	return fmt.Sprintf("%dd%dh%dm", days, hours, mins)
}
