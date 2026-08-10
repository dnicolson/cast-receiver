// Package casttls handles the raw Cast TLS connections: it probes incoming
// bytes, negotiates TLS using the standard Go stack, and falls back to a
// minimal TLS 1.2 server for legacy clients that use a trailing-dot SNI.
package casttls

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
	"time"
)

// HandleConnection probes the raw connection, negotiates TLS (via the standard
// tls.Server or a legacy TLS 1.2 fallback for trailing-dot SNI clients), and
// hands the resulting connection to serve for the Cast protocol loop.
func HandleConnection(conn net.Conn, tlsCfg *tls.Config, cert tls.Certificate, serve func(conn net.Conn)) {
	br := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	hello := probeConnectionStart(conn, br)
	conn.SetReadDeadline(time.Time{})

	if hello != nil && hello.hasTrailingDotSNI() {
		if legacyTLS12FallbackAvailable(hello, cert) {
			legacyConn, err := newLegacyTLS12ServerConn(bufferedConn{Conn: conn, r: br}, br, cert, hello)
			if err != nil {
				log.Printf("session: legacy TLS fallback failed for %s: %v", conn.RemoteAddr(), err)
				conn.Close()
				return
			}
			log.Printf("session: using legacy TLS 1.2 fallback for %s: trailing-dot SNI %q", conn.RemoteAddr(), hello.serverName())
			serve(legacyConn)
			return
		}
		log.Printf("session: trailing-dot SNI from %s but no compatible legacy TLS fallback is available", conn.RemoteAddr())
	}

	cfg := tlsCfg.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		log.Printf(
			"session: client hello from %s: serverName=%q versions=%s ciphers=%s curves=%v alpn=%v sigSchemes=%v",
			conn.RemoteAddr(),
			hello.ServerName,
			tlsVersions(hello.SupportedVersions),
			cipherSuites(hello.CipherSuites),
			hello.SupportedCurves,
			hello.SupportedProtos,
			hello.SignatureSchemes,
		)
		return cfg, nil
	}

	tlsConn := tls.Server(bufferedConn{Conn: conn, r: br}, cfg)
	serve(tlsConn)
}
