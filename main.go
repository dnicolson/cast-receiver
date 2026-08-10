package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"cast-receiver/cast"
	"cast-receiver/casttls"

	"github.com/hashicorp/mdns"
)

var version = "dev" // overridden by goreleaser

const (
	castCapabilityVideo = 0x01
	castCapabilityAudio = 0x04
)

func main() {
	port := flag.Int("port", 8009, "TLS listen port")
	name := flag.String("name", "Go Cast Receiver", "friendly device name")
	dashPort := flag.Int("dashboard", 0, "web dashboard port (0 = disabled)")
	flag.Parse()

	certFile := "cert.pem"
	keyFile := "key.pem"

	cert, err := loadOrCreateTLSCertificate(certFile, keyFile, *name)
	if err != nil {
		log.Fatalf("TLS certificate: %v", err)
	}

	// Extract DER bytes of the TLS cert for device auth signing.
	// ponytail: uses first cert in the chain; add full chain handling if needed
	tlsCertDER := cert.Certificate[0]

	// Create Cast device authenticator.
	authenticator, err := cast.NewAuthenticator(tlsCertDER)
	if err != nil {
		log.Fatalf("auth init: %v", err)
	} else {
		log.Println("device authenticator ready")
	}

	// Create shared receiver for multi-sender support.
	receiver := cast.NewReceiver(authenticator)

	// Optional web dashboard.
	if *dashPort > 0 {
		stopDash, err := cast.StartDashboard(receiver, *dashPort)
		if err != nil {
			log.Fatalf("dashboard: %v", err)
		}
		defer stopDash()
	}

	// mDNS advertisement
	// ponytail: single static TXT record; add full Cast TXT fields (model, capabilities) if senders can't find us
	service, err := mdns.NewMDNSService(
		*name,
		"_googlecast._tcp",
		"",
		"",
		*port,
		[]net.IP{getOutboundIP()},
		[]string{
			fmt.Sprintf("id=%012x", time.Now().Unix()),
			"fn=" + *name,
			"md=GoCastReceiver",
			fmt.Sprintf("ca=%d", castCapabilityVideo|castCapabilityAudio),
			"ic=/setup/icon.png",
		},
	)
	if err != nil {
		log.Fatalf("mdns service: %v", err)
	}

	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		log.Fatalf("mdns server: %v", err)
	}
	defer server.Shutdown()

	log.Printf("advertising %s on _googlecast._tcp port %d", *name, *port)

	// TLS listener
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	log.Printf("listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go casttls.HandleConnection(conn, tlsCfg, cert, func(conn net.Conn) {
			cast.HandleConnection(conn, receiver)
		})
	}
}

func loadOrCreateTLSCertificate(certFile, keyFile, name string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		if err := castTLSCertCompatible(cert.Certificate[0]); err == nil {
			return cert, nil
		} else {
			log.Printf("regenerating TLS certificate: %v", err)
		}
	} else if !os.IsNotExist(err) {
		log.Printf("regenerating TLS certificate: %v", err)
	}

	log.Println("generating self-signed TLS certificate...")
	if err := generateTLSCertificate(certFile, keyFile, name); err != nil {
		return tls.Certificate{}, fmt.Errorf("generate: %w", err)
	}
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load: %w", err)
	}
	if err := castTLSCertCompatible(cert.Certificate[0]); err != nil {
		return tls.Certificate{}, fmt.Errorf("generated incompatible certificate: %w", err)
	}
	return cert, nil
}

func castTLSCertCompatible(certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("server certificate uses %T, want RSA", cert.PublicKey)
	}
	if pub.N.BitLen() < 2048 {
		return fmt.Errorf("RSA key is %d bits, want at least 2048", pub.N.BitLen())
	}
	if !cert.IsCA {
		return fmt.Errorf("certificate missing CA basic constraint")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate is outside its validity window")
	}
	for _, ip := range localCertificateIPs() {
		if !certHasIP(cert, ip) {
			return fmt.Errorf("certificate missing IP SAN %s", ip)
		}
	}
	return nil
}

func generateTLSCertificate(certFile, keyFile, name string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"Go Cast Receiver"},
			CommonName:   name,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           localCertificateIPs(),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(priv)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, keyPEM, 0600)
}

func localCertificateIPs() []net.IP {
	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
	}
	for _, ip := range getAllLocalIPs() {
		ips = appendUniqueIP(ips, ip)
	}
	return ips
}

func getAllLocalIPs() []net.IP {
	var ips []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsMulticast() {
				continue
			}
			ips = appendUniqueIP(ips, ip)
		}
	}
	return ips
}

func appendUniqueIP(ips []net.IP, ip net.IP) []net.IP {
	if ip == nil {
		return ips
	}
	for _, existing := range ips {
		if existing.Equal(ip) {
			return ips
		}
	}
	return append(ips, ip)
}

func certHasIP(cert *x509.Certificate, ip net.IP) bool {
	for _, certIP := range cert.IPAddresses {
		if certIP.Equal(ip) {
			return true
		}
	}
	return false
}

func getOutboundIP() net.IP {
	// ponytail: simplest heuristic; add configurable interface if multi-homed
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.ParseIP("127.0.0.1")
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}
