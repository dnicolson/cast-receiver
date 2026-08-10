package casttls

import (
	"bufio"
	"fmt"
	"log"
	"net"
)

func probeConnectionStart(conn net.Conn, br *bufio.Reader) *tlsClientHelloProbe {
	first, err := br.Peek(8)
	if err != nil {
		log.Printf("session: first bytes from %s: %v", conn.RemoteAddr(), err)
		return nil
	}
	log.Printf("session: first bytes from %s: % x (%s)", conn.RemoteAddr(), first, castProbeKind(first))

	record, err := peekTLSRecord(br)
	if err != nil {
		log.Printf("session: TLS record probe from %s: %v", conn.RemoteAddr(), err)
		return nil
	}
	if record == nil {
		return nil
	}
	log.Printf("session: first TLS record from %s: type=0x%02x version=0x%02x%02x length=%d", conn.RemoteAddr(), record[0], record[1], record[2], len(record)-5)
	hello, err := parseTLSClientHello(record)
	if err != nil {
		log.Printf("session: ClientHello probe from %s: %v", conn.RemoteAddr(), err)
	} else {
		log.Printf("session: ClientHello probe from %s: %s", conn.RemoteAddr(), hello.summary())
	}
	return hello
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func castProbeKind(first []byte) string {
	if len(first) >= 3 && first[0] == 0x16 && first[1] == 0x03 {
		return "tls-handshake-record"
	}
	if len(first) >= 5 && first[0] == 0x15 && first[1] == 0x03 {
		return "tls-alert-record"
	}
	if len(first) >= 5 && first[0] == 0x14 && first[1] == 0x03 {
		return "tls-change-cipher-spec-record"
	}
	if len(first) >= 4 {
		n := int(first[0])<<24 | int(first[1])<<16 | int(first[2])<<8 | int(first[3])
		if n > 0 && n < 1<<20 {
			return fmt.Sprintf("cast-protobuf-or-cleartext-length-%d", n)
		}
	}
	if len(first) >= 3 && string(first[:3]) == "GET" {
		return "http-get"
	}
	if len(first) >= 4 && string(first[:4]) == "POST" {
		return "http-post"
	}
	return "unknown"
}

func peekTLSRecord(br *bufio.Reader) ([]byte, error) {
	header, err := br.Peek(5)
	if err != nil {
		return nil, err
	}
	if header[0] != 0x16 || header[1] != 0x03 {
		return nil, nil
	}
	n := int(header[3])<<8 | int(header[4])
	if n <= 0 || n > 16*1024 {
		return nil, fmt.Errorf("invalid TLS record length %d", n)
	}
	record, err := br.Peek(5 + n)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), record...), nil
}
