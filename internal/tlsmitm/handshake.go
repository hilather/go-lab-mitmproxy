package tlsmitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
)

// ServerConfig is the client-facing tls.Server config (GetConfigForClient).
// connectHost is used when ClientHello has no SNI. Compile-time default ALPN
// is http/1.1; HandshakeServer applies snapshot NextProtos (D46).
func (a *Authority) ServerConfig(connectHost string) *tls.Config {
	return a.serverConfig(connectHost, nil)
}

func (a *Authority) serverConfig(connectHost string, np []string) *tls.Config {
	np = copyNextProtos(np)
	return &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name := ""
			if hello != nil {
				name = hello.ServerName
			}
			if name == "" {
				name = connectHost
			}
			if name == "" {
				return nil, ErrEmptyName
			}
			cert, err := a.leafFor(name)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				Certificates: []tls.Certificate{*cert},
				NextProtos:   append([]string(nil), np...),
				MinVersion:   tls.VersionTLS12,
			}, nil
		},
		NextProtos: append([]string(nil), np...),
		MinVersion: tls.VersionTLS12,
	}
}

// UpstreamConfig is tls.Client config for an already-dialed origin conn.
// Compile-time default ALPN is http/1.1; HandshakeClient applies snapshot NextProtos.
func (a *Authority) UpstreamConfig(sni string) *tls.Config {
	return a.upstreamConfig(sni, nil)
}

func (a *Authority) upstreamConfig(sni string, np []string) *tls.Config {
	cfg := &tls.Config{
		ServerName: sni,
		NextProtos: copyNextProtos(np),
		MinVersion: tls.VersionTLS12,
	}
	if a != nil {
		cfg.RootCAs = a.roots
		cfg.InsecureSkipVerify = a.insecure
	}
	return cfg
}

func copyNextProtos(np []string) []string {
	if len(np) == 0 {
		return []string{ALPN}
	}
	return append([]string(nil), np...)
}

// HandshakeServer runs tls.Server on raw (already accepted) using a minted leaf.
// nextProtos comes from the session snapshot (D46). Empty defaults to http/1.1.
func (a *Authority) HandshakeServer(ctx context.Context, raw net.Conn, connectHost string, nextProtos []string) (*tls.Conn, error) {
	if a == nil {
		return nil, errorsMint("CA is not initialized")
	}
	if raw == nil {
		return nil, errors.New("tlsmitm: nil conn")
	}
	c := tls.Server(raw, a.serverConfig(connectHost, nextProtos))
	if err := handshake(ctx, c); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// HandshakeClient runs tls.Client on raw (already dialed) with default verify on.
// nextProtos comes from the session snapshot (D46). Empty defaults to http/1.1.
func (a *Authority) HandshakeClient(ctx context.Context, raw net.Conn, sni string, nextProtos []string) (*tls.Conn, error) {
	if a == nil {
		return nil, errorsMint("CA is not initialized")
	}
	if raw == nil {
		return nil, errors.New("tlsmitm: nil conn")
	}
	c := tls.Client(raw, a.upstreamConfig(sni, nextProtos))
	if err := handshake(ctx, c); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func handshake(ctx context.Context, c *tls.Conn) error {
	if ctx == nil {
		return c.Handshake()
	}
	return c.HandshakeContext(ctx)
}

// IsVerifyError reports an upstream certificate verification failure.
func IsVerifyError(err error) bool {
	if err == nil {
		return false
	}
	var (
		uae x509.UnknownAuthorityError
		hve x509.HostnameError
		cie x509.CertificateInvalidError
		cve *tls.CertificateVerificationError
	)
	return errors.As(err, &uae) || errors.As(err, &hve) || errors.As(err, &cie) || errors.As(err, &cve)
}
