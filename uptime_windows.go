//go:build windows
// +build windows

package main

import (
	"syscall"
	"time"
)

// systemUptime returns the OS uptime as a rounded duration string on Windows.
func systemUptime() string {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getTick := kernel32.NewProc("GetTickCount64")
	ret, _, _ := getTick.Call()
	ms := uint64(ret)
	return (time.Duration(ms) * time.Millisecond).Round(time.Second).String()
}
