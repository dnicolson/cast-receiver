package casttls

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	legacyTLSRecordChangeCipherSpec = 20
	legacyTLSRecordAlert            = 21
	legacyTLSRecordHandshake        = 22
	legacyTLSRecordApplicationData  = 23

	legacyTLSHandshakeClientKeyExchange = 16
	legacyTLSHandshakeFinished          = 20

	legacyTLSVersion12 = 0x0303

	legacyTLSCipherRSAWithAES128GCM = 0x009c
	legacyTLSEmptyRenegotiationSCSV = 0x00ff

	legacyTLSExtServerName           = 0x0000
	legacyTLSExtExtendedMasterSecret = 0x0017
	legacyTLSExtRenegotiationInfo    = 0xff01

	legacyTLSMaxPlaintext = 16 * 1024
)

type legacyTLS12Conn struct {
	net.Conn

	privateKey *rsa.PrivateKey
	certChain  [][]byte

	clientRandom [32]byte
	serverRandom [32]byte

	readAEAD  cipher.AEAD
	writeAEAD cipher.AEAD
	clientIV  []byte
	serverIV  []byte

	readSeq  uint64
	writeSeq uint64
	readBuf  bytes.Buffer
}

func legacyTLS12FallbackAvailable(hello *tlsClientHelloProbe, cert tls.Certificate) bool {
	if hello == nil || !hello.hasTrailingDotSNI() {
		return false
	}
	if hello.legacyVersion < legacyTLSVersion12 || !hello.hasCipher(legacyTLSCipherRSAWithAES128GCM) {
		return false
	}
	if !hasNullCompression(hello.compression) {
		return false
	}
	_, ok := cert.PrivateKey.(*rsa.PrivateKey)
	return ok && len(cert.Certificate) > 0
}

func newLegacyTLS12ServerConn(conn net.Conn, br *bufio.Reader, cert tls.Certificate, hello *tlsClientHelloProbe) (*legacyTLS12Conn, error) {
	privateKey, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("legacy TLS fallback requires RSA private key, got %T", cert.PrivateKey)
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("legacy TLS fallback requires certificate chain")
	}
	if n, err := br.Discard(len(hello.record)); err != nil {
		return nil, fmt.Errorf("discard probed ClientHello: %w", err)
	} else if n != len(hello.record) {
		return nil, fmt.Errorf("discarded %d ClientHello bytes, want %d", n, len(hello.record))
	}

	c := &legacyTLS12Conn{
		Conn:       conn,
		privateKey: privateKey,
		certChain:  cert.Certificate,
	}
	copy(c.clientRandom[:], hello.random[:])
	if err := c.handshake(hello); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *legacyTLS12Conn) Handshake() error {
	return nil
}

func (c *legacyTLS12Conn) handshake(hello *tlsClientHelloProbe) error {
	if _, err := rand.Read(c.serverRandom[:]); err != nil {
		return fmt.Errorf("server random: %w", err)
	}

	useEMS := hello.hasExtension(legacyTLSExtExtendedMasterSecret)
	serverMessages := c.serverHandshakeMessages(hello, useEMS)

	var transcript bytes.Buffer
	transcript.Write(hello.handshake)
	transcript.Write(serverMessages)

	if err := c.writePlainRecord(legacyTLSRecordHandshake, serverMessages); err != nil {
		return fmt.Errorf("write server hello: %w", err)
	}

	clientKeyExchange, encryptedPreMaster, err := c.readClientKeyExchange()
	if err != nil {
		return err
	}
	transcript.Write(clientKeyExchange)

	preMaster, err := c.decryptPreMasterSecret(encryptedPreMaster)
	if err != nil {
		return err
	}

	var masterSecret []byte
	if useEMS {
		sessionHash := sha256.Sum256(transcript.Bytes())
		masterSecret = tls12PRF(preMaster, "extended master secret", sessionHash[:], 48)
	} else {
		seed := append(append([]byte(nil), c.clientRandom[:]...), c.serverRandom[:]...)
		masterSecret = tls12PRF(preMaster, "master secret", seed, 48)
	}
	if err := c.initApplicationKeys(masterSecret); err != nil {
		return err
	}

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	clientFinished, clientVerify, err := c.readFinished()
	if err != nil {
		return err
	}
	expectedClientVerify := tls12Finished(masterSecret, "client finished", transcript.Bytes())
	if !hmac.Equal(clientVerify, expectedClientVerify) {
		return fmt.Errorf("client Finished verify_data mismatch")
	}
	transcript.Write(clientFinished)

	if err := c.writePlainRecord(legacyTLSRecordChangeCipherSpec, []byte{1}); err != nil {
		return fmt.Errorf("write change_cipher_spec: %w", err)
	}
	serverVerify := tls12Finished(masterSecret, "server finished", transcript.Bytes())
	serverFinished := legacyTLSHandshakeMessage(legacyTLSHandshakeFinished, serverVerify)
	if err := c.writeEncryptedRecord(legacyTLSRecordHandshake, serverFinished); err != nil {
		return fmt.Errorf("write server Finished: %w", err)
	}

	return nil
}

func (c *legacyTLS12Conn) serverHandshakeMessages(hello *tlsClientHelloProbe, useEMS bool) []byte {
	serverHello := c.serverHelloMessage(hello, useEMS)
	certificate := c.certificateMessage()
	done := legacyTLSHandshakeMessage(14, nil)
	msg := make([]byte, 0, len(serverHello)+len(certificate)+len(done))
	msg = append(msg, serverHello...)
	msg = append(msg, certificate...)
	msg = append(msg, done...)
	return msg
}

func (c *legacyTLS12Conn) serverHelloMessage(hello *tlsClientHelloProbe, useEMS bool) []byte {
	var body []byte
	body = appendUint16(body, legacyTLSVersion12)
	body = append(body, c.serverRandom[:]...)
	body = append(body, 0) // empty session ID: no resumption
	body = appendUint16(body, legacyTLSCipherRSAWithAES128GCM)
	body = append(body, 0) // null compression

	var extensions []byte
	if hello.hasCipher(legacyTLSEmptyRenegotiationSCSV) || hello.hasExtension(legacyTLSExtRenegotiationInfo) {
		extensions = appendTLSExtension(extensions, legacyTLSExtRenegotiationInfo, []byte{0})
	}
	if useEMS {
		extensions = appendTLSExtension(extensions, legacyTLSExtExtendedMasterSecret, nil)
	}
	if len(extensions) > 0 {
		body = appendUint16(body, uint16(len(extensions)))
		body = append(body, extensions...)
	}

	return legacyTLSHandshakeMessage(2, body)
}

func (c *legacyTLS12Conn) certificateMessage() []byte {
	var certs []byte
	for _, cert := range c.certChain {
		certs = appendUint24(certs, len(cert))
		certs = append(certs, cert...)
	}
	var body []byte
	body = appendUint24(body, len(certs))
	body = append(body, certs...)
	return legacyTLSHandshakeMessage(11, body)
}

func (c *legacyTLS12Conn) readClientKeyExchange() ([]byte, []byte, error) {
	recordType, _, payload, err := c.readRecord()
	if err != nil {
		return nil, nil, fmt.Errorf("read client key exchange: %w", err)
	}
	if recordType == legacyTLSRecordAlert {
		return nil, nil, legacyTLSAlertError(payload)
	}
	if recordType != legacyTLSRecordHandshake {
		return nil, nil, fmt.Errorf("record type %d before client key exchange", recordType)
	}
	messages, err := splitTLSHandshakeMessages(payload)
	if err != nil {
		return nil, nil, err
	}
	for _, msg := range messages {
		if msg[0] != legacyTLSHandshakeClientKeyExchange {
			return nil, nil, fmt.Errorf("handshake type %d before client key exchange", msg[0])
		}
		encrypted, err := encryptedPreMasterFromClientKeyExchange(msg[4:])
		return msg, encrypted, err
	}
	return nil, nil, fmt.Errorf("missing client key exchange")
}

func encryptedPreMasterFromClientKeyExchange(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("client key exchange body too short: %d", len(body))
	}
	n := int(body[0])<<8 | int(body[1])
	if n == len(body)-2 {
		return body[2:], nil
	}
	return body, nil
}

func (c *legacyTLS12Conn) decryptPreMasterSecret(encrypted []byte) ([]byte, error) {
	preMaster := make([]byte, 48)
	if _, err := rand.Read(preMaster); err != nil {
		return nil, fmt.Errorf("premaster fallback: %w", err)
	}
	candidate := append([]byte(nil), preMaster...)
	if err := rsa.DecryptPKCS1v15SessionKey(rand.Reader, c.privateKey, encrypted, candidate); err != nil {
		return nil, fmt.Errorf("decrypt premaster: %w", err)
	}
	return candidate, nil
}

func (c *legacyTLS12Conn) initApplicationKeys(masterSecret []byte) error {
	seed := append(append([]byte(nil), c.serverRandom[:]...), c.clientRandom[:]...)
	keyBlock := tls12PRF(masterSecret, "key expansion", seed, 40)

	clientKey := keyBlock[:16]
	serverKey := keyBlock[16:32]
	c.clientIV = append([]byte(nil), keyBlock[32:36]...)
	c.serverIV = append([]byte(nil), keyBlock[36:40]...)

	clientBlock, err := aes.NewCipher(clientKey)
	if err != nil {
		return fmt.Errorf("client cipher: %w", err)
	}
	serverBlock, err := aes.NewCipher(serverKey)
	if err != nil {
		return fmt.Errorf("server cipher: %w", err)
	}
	c.readAEAD, err = cipher.NewGCM(clientBlock)
	if err != nil {
		return fmt.Errorf("client GCM: %w", err)
	}
	c.writeAEAD, err = cipher.NewGCM(serverBlock)
	if err != nil {
		return fmt.Errorf("server GCM: %w", err)
	}
	return nil
}

func (c *legacyTLS12Conn) readChangeCipherSpec() error {
	recordType, _, payload, err := c.readRecord()
	if err != nil {
		return fmt.Errorf("read change_cipher_spec: %w", err)
	}
	if recordType == legacyTLSRecordAlert {
		return legacyTLSAlertError(payload)
	}
	if recordType != legacyTLSRecordChangeCipherSpec || len(payload) != 1 || payload[0] != 1 {
		return fmt.Errorf("expected change_cipher_spec, got type=%d payload=% x", recordType, payload)
	}
	return nil
}

func (c *legacyTLS12Conn) readFinished() ([]byte, []byte, error) {
	recordType, _, payload, err := c.readEncryptedRecord()
	if err != nil {
		return nil, nil, fmt.Errorf("read Finished: %w", err)
	}
	if recordType == legacyTLSRecordAlert {
		return nil, nil, legacyTLSAlertError(payload)
	}
	if recordType != legacyTLSRecordHandshake {
		return nil, nil, fmt.Errorf("expected encrypted Finished handshake, got record type %d", recordType)
	}
	messages, err := splitTLSHandshakeMessages(payload)
	if err != nil {
		return nil, nil, err
	}
	if len(messages) != 1 || messages[0][0] != legacyTLSHandshakeFinished {
		return nil, nil, fmt.Errorf("expected Finished, got %d handshake messages", len(messages))
	}
	body := messages[0][4:]
	if len(body) != 12 {
		return nil, nil, fmt.Errorf("Finished verify_data length %d, want 12", len(body))
	}
	return messages[0], body, nil
}

func (c *legacyTLS12Conn) Read(p []byte) (int, error) {
	for c.readBuf.Len() == 0 {
		recordType, _, payload, err := c.readEncryptedRecord()
		if err != nil {
			return 0, err
		}
		switch recordType {
		case legacyTLSRecordApplicationData:
			if len(payload) > 0 {
				c.readBuf.Write(payload)
			}
		case legacyTLSRecordAlert:
			return 0, legacyTLSAlertError(payload)
		case legacyTLSRecordChangeCipherSpec:
			continue
		default:
			return 0, fmt.Errorf("unexpected encrypted TLS record type %d", recordType)
		}
	}
	return c.readBuf.Read(p)
}

func (c *legacyTLS12Conn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > legacyTLSMaxPlaintext {
			n = legacyTLSMaxPlaintext
		}
		if err := c.writeEncryptedRecord(legacyTLSRecordApplicationData, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *legacyTLS12Conn) readRecord() (byte, uint16, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, 0, nil, err
	}
	recordType := header[0]
	version := uint16(header[1])<<8 | uint16(header[2])
	n := int(header[3])<<8 | int(header[4])
	if n < 0 || n > legacyTLSMaxPlaintext+2048 {
		return 0, 0, nil, fmt.Errorf("TLS record length %d invalid", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return 0, 0, nil, err
	}
	return recordType, version, payload, nil
}

func (c *legacyTLS12Conn) readEncryptedRecord() (byte, uint16, []byte, error) {
	recordType, version, payload, err := c.readRecord()
	if err != nil {
		return 0, 0, nil, err
	}
	if c.readAEAD == nil {
		return 0, 0, nil, fmt.Errorf("read cipher is not initialized")
	}
	if len(payload) < 8+c.readAEAD.Overhead() {
		return 0, 0, nil, fmt.Errorf("encrypted record too short: %d", len(payload))
	}
	explicitNonce := payload[:8]
	ciphertext := payload[8:]
	plainLen := len(ciphertext) - c.readAEAD.Overhead()
	nonce := append(append([]byte(nil), c.clientIV...), explicitNonce...)
	aad := tls12AdditionalData(c.readSeq, recordType, version, plainLen)
	plain, err := c.readAEAD.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return 0, 0, nil, err
	}
	c.readSeq++
	return recordType, version, plain, nil
}

func (c *legacyTLS12Conn) writePlainRecord(recordType byte, payload []byte) error {
	if len(payload) == 0 {
		return writeTLSRecord(c.Conn, recordType, legacyTLSVersion12, nil)
	}
	for len(payload) > 0 {
		n := len(payload)
		if n > legacyTLSMaxPlaintext {
			n = legacyTLSMaxPlaintext
		}
		if err := writeTLSRecord(c.Conn, recordType, legacyTLSVersion12, payload[:n]); err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func (c *legacyTLS12Conn) writeEncryptedRecord(recordType byte, plaintext []byte) error {
	if c.writeAEAD == nil {
		return fmt.Errorf("write cipher is not initialized")
	}
	var explicitNonce [8]byte
	binary.BigEndian.PutUint64(explicitNonce[:], c.writeSeq)
	nonce := append(append([]byte(nil), c.serverIV...), explicitNonce[:]...)
	aad := tls12AdditionalData(c.writeSeq, recordType, legacyTLSVersion12, len(plaintext))
	ciphertext := c.writeAEAD.Seal(nil, nonce, plaintext, aad)

	payload := make([]byte, 0, len(explicitNonce)+len(ciphertext))
	payload = append(payload, explicitNonce[:]...)
	payload = append(payload, ciphertext...)
	c.writeSeq++
	return writeTLSRecord(c.Conn, recordType, legacyTLSVersion12, payload)
}

func writeTLSRecord(w io.Writer, recordType byte, version uint16, payload []byte) error {
	var header [5]byte
	header[0] = recordType
	binary.BigEndian.PutUint16(header[1:3], version)
	binary.BigEndian.PutUint16(header[3:5], uint16(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		p = p[n:]
	}
	return nil
}

func splitTLSHandshakeMessages(payload []byte) ([][]byte, error) {
	var messages [][]byte
	for len(payload) > 0 {
		if len(payload) < 4 {
			return nil, fmt.Errorf("handshake header truncated: %d bytes", len(payload))
		}
		n := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		if len(payload) < 4+n {
			return nil, fmt.Errorf("handshake body truncated: need %d, have %d", n, len(payload)-4)
		}
		messages = append(messages, append([]byte(nil), payload[:4+n]...))
		payload = payload[4+n:]
	}
	return messages, nil
}

func legacyTLSHandshakeMessage(handshakeType byte, body []byte) []byte {
	msg := []byte{handshakeType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	msg = append(msg, body...)
	return msg
}

func appendTLSExtension(dst []byte, extType uint16, data []byte) []byte {
	dst = appendUint16(dst, extType)
	dst = appendUint16(dst, uint16(len(data)))
	return append(dst, data...)
}

func appendUint16(dst []byte, v uint16) []byte {
	return append(dst, byte(v>>8), byte(v))
}

func appendUint24(dst []byte, v int) []byte {
	return append(dst, byte(v>>16), byte(v>>8), byte(v))
}

func tls12AdditionalData(seq uint64, recordType byte, version uint16, plainLen int) []byte {
	var aad [13]byte
	binary.BigEndian.PutUint64(aad[0:8], seq)
	aad[8] = recordType
	binary.BigEndian.PutUint16(aad[9:11], version)
	binary.BigEndian.PutUint16(aad[11:13], uint16(plainLen))
	return aad[:]
}

func tls12Finished(masterSecret []byte, label string, transcript []byte) []byte {
	h := sha256.Sum256(transcript)
	return tls12PRF(masterSecret, label, h[:], 12)
}

func tls12PRF(secret []byte, label string, seed []byte, n int) []byte {
	return pHash(secret, append([]byte(label), seed...), n)
}

func pHash(secret, seed []byte, n int) []byte {
	var out []byte
	a := seed
	for len(out) < n {
		mac := hmac.New(sha256.New, secret)
		mac.Write(a)
		a = mac.Sum(nil)

		mac = hmac.New(sha256.New, secret)
		mac.Write(a)
		mac.Write(seed)
		out = mac.Sum(out)
	}
	return out[:n]
}

func hasNullCompression(methods []byte) bool {
	for _, method := range methods {
		if method == 0 {
			return true
		}
	}
	return false
}

func legacyTLSAlertError(payload []byte) error {
	if len(payload) >= 2 && payload[1] == 0 {
		return io.EOF
	}
	if len(payload) >= 2 {
		return fmt.Errorf("TLS alert level=%d description=%d", payload[0], payload[1])
	}
	return fmt.Errorf("TLS alert payload=% x", payload)
}
