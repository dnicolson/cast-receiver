package casttls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestLegacyTLS12FallbackAvailableRequiresTrailingDotSNI(t *testing.T) {
	cert := testRSACert(t)

	trailingDotRecord := testClientHelloRecord([]testTLSExtension{
		{typ: 0x0000, data: testServerNameExtension("receiver.local.")},
	})
	trailingDotHello, err := parseTLSClientHello(trailingDotRecord)
	if err != nil {
		t.Fatal(err)
	}
	if !legacyTLS12FallbackAvailable(trailingDotHello, cert) {
		t.Fatal("legacy TLS fallback should be available for trailing-dot SNI with RSA GCM")
	}

	normalRecord := testClientHelloRecord([]testTLSExtension{
		{typ: 0x0000, data: testServerNameExtension("receiver.local")},
	})
	normalHello, err := parseTLSClientHello(normalRecord)
	if err != nil {
		t.Fatal(err)
	}
	if legacyTLS12FallbackAvailable(normalHello, cert) {
		t.Fatal("legacy TLS fallback should not be used for normal SNI")
	}
}

func testRSACert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
