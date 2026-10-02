// Command containerorigin is a test-only origin fixture, never shipped in LabMITM.
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
)

func fixtureHandler(secure bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "container-smoke"
		if secure {
			body += "-https"
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, body)
	})
}
func serveOrigins(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	plain, err := net.Listen("tcp", ":8080")
	if err != nil {
		return err
	}
	defer func() { _ = plain.Close() }()
	secure, err := net.Listen("tcp", ":8443")
	if err != nil {
		return err
	}
	defer func() { _ = secure.Close() }()
	secure = tls.NewListener(secure, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	failures := make(chan error, 2)
	go func() { failures <- http.Serve(plain, fixtureHandler(false)) }()
	go func() { failures <- http.Serve(secure, fixtureHandler(true)) }()
	_, _ = fmt.Println("origin ready http=:8080 https=:8443")
	return <-failures
}
func main() {
	if err := serveOrigins("/origin-cert.pem", "/origin-key.pem"); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "container origin:", err)
		os.Exit(1)
	}
}
