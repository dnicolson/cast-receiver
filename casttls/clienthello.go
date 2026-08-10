package casttls

import (
	"crypto/tls"
	"fmt"
	"strings"
)

type tlsClientHelloProbe struct {
	record        []byte
	handshake     []byte
	legacyVersion uint16
	random        [32]byte
	sessionID     []byte
	ciphers       []uint16
	compression   []byte
	extensions    []tlsExtensionProbe
	serverNames   []tlsServerNameProbe
}

type tlsExtensionProbe struct {
	typ       uint16
	data      []byte
	duplicate bool
}

type tlsServerNameProbe struct {
	typ  uint8
	name string
}

func parseTLSClientHelloRecord(record []byte) (string, error) {
	hello, err := parseTLSClientHello(record)
	if err != nil {
		return "", err
	}
	return hello.summary(), nil
}

func parseTLSClientHello(record []byte) (*tlsClientHelloProbe, error) {
	if len(record) < 9 {
		return nil, fmt.Errorf("record too short: %d bytes", len(record))
	}
	if record[0] != 0x16 {
		return nil, fmt.Errorf("record type 0x%02x, want handshake", record[0])
	}
	recordLen := int(record[3])<<8 | int(record[4])
	if recordLen != len(record)-5 {
		return nil, fmt.Errorf("record length = %d, available = %d", recordLen, len(record)-5)
	}
	handshake := record[5:]
	if handshake[0] != 0x01 {
		return nil, fmt.Errorf("handshake type 0x%02x, want ClientHello", handshake[0])
	}
	handshakeLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if handshakeLen != len(handshake)-4 {
		return nil, fmt.Errorf("ClientHello length = %d, available = %d", handshakeLen, len(handshake)-4)
	}
	p := 4
	if len(handshake[p:]) < 2+32+1 {
		return nil, fmt.Errorf("ClientHello fixed fields truncated at %d", p)
	}
	hello := &tlsClientHelloProbe{
		record:        append([]byte(nil), record...),
		handshake:     append([]byte(nil), handshake...),
		legacyVersion: uint16(handshake[p])<<8 | uint16(handshake[p+1]),
	}
	p += 2
	copy(hello.random[:], handshake[p:p+32])
	p += 32

	sessionIDLen := int(handshake[p])
	p++
	if len(handshake[p:]) < sessionIDLen+2 {
		return nil, fmt.Errorf("session ID length %d exceeds remaining %d", sessionIDLen, len(handshake[p:]))
	}
	hello.sessionID = append([]byte(nil), handshake[p:p+sessionIDLen]...)
	p += sessionIDLen

	cipherLen := int(handshake[p])<<8 | int(handshake[p+1])
	p += 2
	if cipherLen == 0 || cipherLen%2 != 0 || len(handshake[p:]) < cipherLen+1 {
		return nil, fmt.Errorf("cipher suite length %d invalid with remaining %d", cipherLen, len(handshake[p:]))
	}
	hello.ciphers = make([]uint16, 0, cipherLen/2)
	for i := 0; i < cipherLen; i += 2 {
		hello.ciphers = append(hello.ciphers, uint16(handshake[p+i])<<8|uint16(handshake[p+i+1]))
	}
	p += cipherLen

	compressionLen := int(handshake[p])
	p++
	if compressionLen == 0 || len(handshake[p:]) < compressionLen {
		return nil, fmt.Errorf("compression methods length %d invalid with remaining %d", compressionLen, len(handshake[p:]))
	}
	hello.compression = append([]byte(nil), handshake[p:p+compressionLen]...)
	p += compressionLen

	if p == len(handshake) {
		return hello, nil
	}
	if len(handshake[p:]) < 2 {
		return nil, fmt.Errorf("extension vector length missing at %d", p)
	}
	extensionsLen := int(handshake[p])<<8 | int(handshake[p+1])
	p += 2
	if extensionsLen != len(handshake)-p {
		return nil, fmt.Errorf("extensions length = %d, available = %d", extensionsLen, len(handshake)-p)
	}

	seen := map[uint16]bool{}
	extensionsEnd := p + extensionsLen
	for p < extensionsEnd {
		if extensionsEnd-p < 4 {
			return nil, fmt.Errorf("extension header truncated with %d bytes left", extensionsEnd-p)
		}
		extType := uint16(handshake[p])<<8 | uint16(handshake[p+1])
		extLen := int(handshake[p+2])<<8 | int(handshake[p+3])
		p += 4
		if extensionsEnd-p < extLen {
			return nil, fmt.Errorf("extension 0x%04x length %d exceeds remaining %d", extType, extLen, extensionsEnd-p)
		}
		extData := handshake[p : p+extLen]
		p += extLen

		duplicate := seen[extType]
		seen[extType] = true
		hello.extensions = append(hello.extensions, tlsExtensionProbe{
			typ:       extType,
			data:      append([]byte(nil), extData...),
			duplicate: duplicate,
		})
		if extType == 0x0000 {
			hello.serverNames = append(hello.serverNames, parseServerNameProbes(extData)...)
		}
	}

	return hello, nil
}

func (h *tlsClientHelloProbe) summary() string {
	extensions := "none"
	if len(h.extensions) > 0 {
		extSummaries := make([]string, 0, len(h.extensions))
		for _, ext := range h.extensions {
			duplicate := ""
			if ext.duplicate {
				duplicate = ",duplicate"
			}
			extSummaries = append(extSummaries, fmt.Sprintf("0x%04x(len=%d%s%s)", ext.typ, len(ext.data), duplicate, extensionProbeNote(ext.typ, ext.data)))
		}
		extensions = fmt.Sprint(extSummaries)
	}
	return fmt.Sprintf(
		"legacyVersion=0x%04x sessionID=%d ciphers=%s compression=% x extensions=%s",
		h.legacyVersion,
		len(h.sessionID),
		cipherSuites(h.ciphers),
		h.compression,
		extensions,
	)
}

func (h *tlsClientHelloProbe) hasCipher(id uint16) bool {
	for _, cipher := range h.ciphers {
		if cipher == id {
			return true
		}
	}
	return false
}

func (h *tlsClientHelloProbe) hasExtension(id uint16) bool {
	for _, ext := range h.extensions {
		if ext.typ == id {
			return true
		}
	}
	return false
}

func (h *tlsClientHelloProbe) hasTrailingDotSNI() bool {
	for _, name := range h.serverNames {
		if name.typ == 0 && strings.HasSuffix(name.name, ".") {
			return true
		}
	}
	return false
}

func (h *tlsClientHelloProbe) serverName() string {
	for _, name := range h.serverNames {
		if name.typ == 0 {
			return name.name
		}
	}
	return ""
}

func parseServerNameProbes(data []byte) []tlsServerNameProbe {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	if listLen == 0 || listLen != len(data)-2 {
		return nil
	}
	p := 2
	var names []tlsServerNameProbe
	for p < len(data) {
		if len(data[p:]) < 3 {
			return nil
		}
		nameType := data[p]
		nameLen := int(data[p+1])<<8 | int(data[p+2])
		p += 3
		if nameLen == 0 || len(data[p:]) < nameLen {
			return nil
		}
		names = append(names, tlsServerNameProbe{typ: nameType, name: string(data[p : p+nameLen])})
		p += nameLen
	}
	return names
}

func extensionProbeNote(extType uint16, data []byte) string {
	switch extType {
	case 0x0000:
		return serverNameProbeNote(data)
	case 0x000a:
		if len(data) < 2 {
			return ",supported_groups=truncated"
		}
		n := int(data[0])<<8 | int(data[1])
		if n == 0 || n%2 != 0 || n != len(data)-2 {
			return fmt.Sprintf(",supported_groups=invalid-vector-%d", n)
		}
	case 0x000b:
		if len(data) < 1 {
			return ",ec_points=truncated"
		}
		n := int(data[0])
		if n == 0 || n != len(data)-1 {
			return fmt.Sprintf(",ec_points=invalid-vector-%d", n)
		}
	case 0x000d:
		if len(data) < 2 {
			return ",sig_algs=truncated"
		}
		n := int(data[0])<<8 | int(data[1])
		if n == 0 || n%2 != 0 || n != len(data)-2 {
			return fmt.Sprintf(",sig_algs=invalid-vector-%d", n)
		}
	case 0x0010:
		if len(data) < 2 {
			return ",alpn=truncated"
		}
		n := int(data[0])<<8 | int(data[1])
		if n == 0 || n != len(data)-2 {
			return fmt.Sprintf(",alpn=invalid-vector-%d", n)
		}
	case 0x002b:
		if len(data) < 1 {
			return ",supported_versions=truncated"
		}
		n := int(data[0])
		if n == 0 || n%2 != 0 || n != len(data)-1 {
			return fmt.Sprintf(",supported_versions=invalid-vector-%d", n)
		}
	}
	return ""
}

func serverNameProbeNote(data []byte) string {
	if len(data) < 2 {
		return ",sni=truncated"
	}
	listLen := int(data[0])<<8 | int(data[1])
	if listLen == 0 {
		return ",sni=empty-list"
	}
	if listLen != len(data)-2 {
		return fmt.Sprintf(",sni=invalid-list-%d", listLen)
	}
	p := 2
	var names []string
	for p < len(data) {
		if len(data[p:]) < 3 {
			return fmt.Sprintf(",sni=truncated-name-at-%d", p)
		}
		nameType := data[p]
		nameLen := int(data[p+1])<<8 | int(data[p+2])
		p += 3
		if nameLen == 0 || len(data[p:]) < nameLen {
			return fmt.Sprintf(",sni=invalid-name-%d", nameLen)
		}
		name := string(data[p : p+nameLen])
		note := fmt.Sprintf("%d:%q", nameType, name)
		if nameType == 0 && strings.HasSuffix(name, ".") {
			note += "(trailing-dot)"
		}
		names = append(names, note)
		p += nameLen
	}
	return ",sni=" + fmt.Sprint(names)
}

func tlsVersions(versions []uint16) []string {
	out := make([]string, 0, len(versions))
	for _, version := range versions {
		switch version {
		case tls.VersionTLS10:
			out = append(out, "TLS1.0")
		case tls.VersionTLS11:
			out = append(out, "TLS1.1")
		case tls.VersionTLS12:
			out = append(out, "TLS1.2")
		case tls.VersionTLS13:
			out = append(out, "TLS1.3")
		default:
			out = append(out, fmt.Sprintf("0x%04x", version))
		}
	}
	return out
}

func cipherSuites(ids []uint16) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, tls.CipherSuiteName(id))
	}
	return out
}
