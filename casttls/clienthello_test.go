package casttls

import (
	"strings"
	"testing"
)

func TestCastProbeKind(t *testing.T) {
	tests := []struct {
		name  string
		first []byte
		want  string
	}{
		{name: "tls handshake", first: []byte{0x16, 0x03, 0x01, 0x00, 0x9f, 0x01, 0x00, 0x00}, want: "tls-handshake-record"},
		{name: "tls alert", first: []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32, 0x00}, want: "tls-alert-record"},
		{name: "cast length", first: []byte{0x00, 0x00, 0x00, 0x40, 0x08, 0x00, 0x12, 0x06}, want: "cast-protobuf-or-cleartext-length-64"},
		{name: "http", first: []byte("GET /foo"), want: "http-get"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := castProbeKind(tt.first); got != tt.want {
				t.Fatalf("castProbeKind(% x) = %q, want %q", tt.first, got, tt.want)
			}
		})
	}
}

func TestParseTLSClientHelloRecordNotesMalformedSNI(t *testing.T) {
	record := testClientHelloRecord([]testTLSExtension{
		{typ: 0x0000, data: []byte{0x00, 0x00}},
		{typ: 0x000a, data: []byte{0x00, 0x02, 0x00, 0x17}},
		{typ: 0x000b, data: []byte{0x01, 0x00}},
		{typ: 0x000d, data: []byte{0x00, 0x02, 0x04, 0x01}},
	})

	summary, err := parseTLSClientHelloRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "sni=empty-list") {
		t.Fatalf("summary missing malformed SNI note: %s", summary)
	}
}

func TestParseTLSClientHelloRecordNotesDuplicateExtension(t *testing.T) {
	record := testClientHelloRecord([]testTLSExtension{
		{typ: 0x0017, data: nil},
		{typ: 0x0017, data: nil},
	})

	summary, err := parseTLSClientHelloRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "duplicate") {
		t.Fatalf("summary missing duplicate extension note: %s", summary)
	}
}

func TestParseTLSClientHelloRecordNotesTrailingDotSNI(t *testing.T) {
	record := testClientHelloRecord([]testTLSExtension{
		{typ: 0x0000, data: testServerNameExtension("receiver.local.")},
	})

	summary, err := parseTLSClientHelloRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "(trailing-dot)") {
		t.Fatalf("summary missing trailing-dot SNI note: %s", summary)
	}

	hello, err := parseTLSClientHello(record)
	if err != nil {
		t.Fatal(err)
	}
	if !hello.hasTrailingDotSNI() {
		t.Fatal("ClientHello should have trailing-dot SNI")
	}
	if got := hello.serverName(); got != "receiver.local." {
		t.Fatalf("serverName = %q, want receiver.local.", got)
	}
}

type testTLSExtension struct {
	typ  uint16
	data []byte
}

func testClientHelloRecord(extensions []testTLSExtension) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x04, 0x00, 0x9c, 0xc0, 0x2f)
	body = append(body, 0x01, 0x00)

	var extBytes []byte
	for _, ext := range extensions {
		extBytes = append(extBytes, byte(ext.typ>>8), byte(ext.typ))
		extBytes = append(extBytes, byte(len(ext.data)>>8), byte(len(ext.data)))
		extBytes = append(extBytes, ext.data...)
	}
	body = append(body, byte(len(extBytes)>>8), byte(len(extBytes)))
	body = append(body, extBytes...)

	var handshake []byte
	handshake = append(handshake, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	var record []byte
	record = append(record, 0x16, 0x03, 0x01, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}

func testServerNameExtension(name string) []byte {
	nameBytes := []byte(name)
	var nameList []byte
	nameList = append(nameList, 0)
	nameList = append(nameList, byte(len(nameBytes)>>8), byte(len(nameBytes)))
	nameList = append(nameList, nameBytes...)

	var data []byte
	data = append(data, byte(len(nameList)>>8), byte(len(nameList)))
	data = append(data, nameList...)
	return data
}
