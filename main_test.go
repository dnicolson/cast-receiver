package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateTLSCertificateCreatesCastCompatibleCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	if err := generateTLSCertificate(certFile, keyFile, "Test Receiver"); err != nil {
		t.Fatal(err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := castTLSCertCompatible(cert.Certificate[0]); err != nil {
		t.Fatalf("generated certificate is incompatible: %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := leaf.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("PublicKey = %T, want RSA", leaf.PublicKey)
	}
	if !leaf.IsCA {
		t.Fatal("generated certificate should have CA basic constraint")
	}
}

func TestCastTLSCertCompatibleRejectsECDSA(t *testing.T) {
	certDER, _, err := generateLegacyECDSATestCert()
	if err != nil {
		t.Fatal(err)
	}

	err = castTLSCertCompatible(certDER)
	if err == nil {
		t.Fatal("castTLSCertCompatible accepted ECDSA cert")
	}
	if !strings.Contains(err.Error(), "want RSA") {
		t.Fatalf("error = %q, want RSA rejection", err)
	}
}

func TestLoadOrCreateTLSCertificateRegeneratesLegacyCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	certDER, keyDER, err := generateLegacyECDSATestCert()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}

	cert, err := loadOrCreateTLSCertificate(certFile, keyFile, "Test Receiver")
	if err != nil {
		t.Fatal(err)
	}
	if err := castTLSCertCompatible(cert.Certificate[0]); err != nil {
		t.Fatalf("regenerated certificate is incompatible: %v", err)
	}
}

func generateLegacyECDSATestCert() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           localCertificateIPs(),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return certDER, keyDER, nil
}
