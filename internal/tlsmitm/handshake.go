package tlsmitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
)

// ServerConfig is the client-facing tls.Server config (GetConfigForClient).
// connectHost is used when ClientHello has no SNI.
func (a *Authority) ServerConfig(connectHost string) *tls.Config {
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
				NextProtos:   append([]string(nil), nextProtos...),
				MinVersion:   tls.VersionTLS12,
			}, nil
		},
		NextProtos: append([]string(nil), nextProtos...),
		MinVersion: tls.VersionTLS12,
	}
}

// UpstreamConfig is tls.Client config for an already-dialed origin conn.
func (a *Authority) UpstreamConfig(sni string) *tls.Config {
	cfg := &tls.Config{
		ServerName: sni,
		NextProtos: append([]string(nil), nextProtos...),
		MinVersion: tls.VersionTLS12,
	}
	if a != nil {
		cfg.RootCAs = a.roots
		cfg.InsecureSkipVerify = a.insecure
	}
	return cfg
}

// HandshakeServer runs tls.Server on raw (already accepted) using a minted leaf.
func (a *Authority) HandshakeServer(ctx context.Context, raw net.Conn, connectHost string) (*tls.Conn, error) {
	if a == nil {
		return nil, errorsMint("CA is not initialized")
	}
	if raw == nil {
		return nil, errors.New("tlsmitm: nil conn")
	}
	c := tls.Server(raw, a.ServerConfig(connectHost))
	if err := handshake(ctx, c); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// HandshakeClient runs tls.Client on raw (already dialed) with default verify on.
func (a *Authority) HandshakeClient(ctx context.Context, raw net.Conn, sni string) (*tls.Conn, error) {
	if a == nil {
		return nil, errorsMint("CA is not initialized")
	}
	if raw == nil {
		return nil, errors.New("tlsmitm: nil conn")
	}
	c := tls.Client(raw, a.UpstreamConfig(sni))
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
