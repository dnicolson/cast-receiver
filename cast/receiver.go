package cast

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"log"
	"math/big"
	"sync"
	"time"

	pb "cast-receiver/castpb"

	"google.golang.org/protobuf/proto"
)

// Authenticator holds credentials for Cast device authentication.
// ponytail: single auth keypair per run; rotation if auth becomes a security concern
type Authenticator struct {
	AuthCertDER []byte
	AuthKey     *ecdsa.PrivateKey
	TLSCertDER  []byte
}

// NewAuthenticator generates a fresh auth keypair and self-signed cert.
func NewAuthenticator(tlsCertDER []byte) (*Authenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &Authenticator{
		AuthCertDER: certDER,
		AuthKey:     key,
		TLSCertDER:  tlsCertDER,
	}, nil
}

// SignTLS returns an ECDSA signature of the SHA256 hash of the TLS cert DER.
func (a *Authenticator) SignTLS() ([]byte, error) {
	h := sha256.Sum256(a.TLSCertDER)
	r, s, err := ecdsa.Sign(rand.Reader, a.AuthKey, h[:])
	if err != nil {
		return nil, err
	}
	return append(r.Bytes(), s.Bytes()...), nil
}

// Receiver holds shared Cast receiver state visible to all connected senders.
// ponytail: global lock; per-session locks only if contention appears
type Receiver struct {
	mu          sync.Mutex
	sessions    map[string]*Session
	Media       *MediaSession
	auth        *Authenticator
	volume      Volume
	nextSession int
}

// NewReceiver creates a Receiver.
func NewReceiver(auth *Authenticator) *Receiver {
	return &Receiver{
		sessions: make(map[string]*Session),
		Media: &MediaSession{
			PlayerState: "IDLE",
		},
		auth:   auth,
		volume: Volume{Level: 1, Muted: false},
	}
}

// Register adds a session. Returns a unique sourceID.
func (r *Receiver) Register(s *Session) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextSession++
	id := "sender-" + itoa(r.nextSession)
	s.sourceID = id
	r.sessions[id] = s
	log.Printf("receiver: registered %s (%d sessions)", id, len(r.sessions))
	return id
}

// Unregister removes a session.
func (r *Receiver) Unregister(sourceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, sourceID)
	log.Printf("receiver: unregistered %s (%d left)", sourceID, len(r.sessions))
}

// Broadcast sends a message on a namespace to all sessions except the sender.
func (r *Receiver) Broadcast(src, ns string, payload json.RawMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.sessions {
		if id == src {
			continue
		}
		s.sendRaw(ns, payload)
	}
}

// SendTo sends a message to a specific session.
func (r *Receiver) SendTo(dest, ns string, payload json.RawMessage) {
	r.mu.Lock()
	s, ok := r.sessions[dest]
	r.mu.Unlock()
	if ok {
		s.sendRaw(ns, payload)
	}
}

// Authenticator returns the device authenticator.
func (r *Receiver) Authenticator() *Authenticator { return r.auth }

// Volume returns the current volume.
func (r *Receiver) Volume() Volume {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.volume
}

// SetVolume updates the volume.
func (r *Receiver) SetVolume(v Volume) {
	r.mu.Lock()
	r.volume = v
	r.mu.Unlock()
}

// AppStatus returns the app list for RECEIVER_STATUS.
func (r *Receiver) AppStatus() []AppStatus {
	return []AppStatus{{
		AppID:       "CC1AD845",
		DisplayName: "Default Media Receiver",
		Namespaces:  []string{nsMedia},
		SessionID:   "session-1",
		StatusText:  "Ready To Cast",
		TransportID: "web-1",
	}}
}

// SendCastMessage builds and writes a CastMessage on an io.Writer.
func SendCastMessage(w interface{ Write([]byte) (int, error) }, src, dest, ns string, payload []byte, binary bool) {
	pt := pb.CastMessage_STRING
	if binary {
		pt = pb.CastMessage_BINARY
	}
	msg := &pb.CastMessage{
		ProtocolVersion: pb.CastMessage_CASTV2_1_0.Enum(),
		SourceId:        proto.String(src),
		DestinationId:   proto.String(dest),
		Namespace:       proto.String(ns),
		PayloadType:     pt.Enum(),
	}
	if binary {
		msg.PayloadBinary = payload
	} else {
		msg.PayloadUtf8 = proto.String(string(payload))
	}
	if err := WriteMessage(w, msg); err != nil {
		log.Printf("send error: %v", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
