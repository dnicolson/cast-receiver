package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"github.com/hashicorp/mdns"
)

var version = "dev" // overridden by goreleaser

func main() {
	port := flag.Int("port", 8009, "TLS listen port")
	name := flag.String("name", "Go Cast Receiver", "friendly device name")
	flag.Parse()

	certFile := "cert.pem"
	keyFile := "key.pem"

	// Generate self-signed TLS cert if it doesn't exist
	// ponytail: generate once, reuse; add cert rotation if running 24/7 for weeks
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Println("generating self-signed TLS certificate...")
		if err := generateCert(certFile, keyFile); err != nil {
			log.Fatalf("cert generation: %v", err)
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("load cert: %v", err)
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
			"ca=2800",
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
	// ponytail: no client cert verification; add if senders require mutual TLS
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", *port), tlsCfg)
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
		tlsConn := conn.(*tls.Conn)
		// ponytail: sequential handling; add goroutine per conn if multiple senders need simultaneous support
		go cast.HandleConnection(tlsConn, receiver)
	}
}

func generateCert(certFile, keyFile string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"Go Cast Receiver"},
			CommonName:   "Go Cast Receiver",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, keyPEM, 0600)
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
