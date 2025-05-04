package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// choosePort picks a port: tries flagPort, defaultPort, or any free port
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

// available checks if a TCP port is available
func available(p int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// freePort asks the OS for a free TCP port (>0)
func freePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	addr := l.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// randomString generates an alphanumeric string of length n
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

// fileExists reports whether the given path exists
func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// generateSelfSigned creates PEM encoded cert/key pair for localhost
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

	cf, err := os.Create(certOut)
	if err != nil {
		return err
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		cf.Close()
		return err
	}
	cf.Close()

	kf, err := os.Create(keyOut)
	if err != nil {
		return err
	}
	if err := pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		kf.Close()
		return err
	}
	kf.Close()
	return nil
}

// firstNonLoopbackIP returns the first active non-loopback IPv4 or "localhost"
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

// ternary returns a if cond is true, else b
func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
