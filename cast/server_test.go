package cast

import (
	"bytes"
	"encoding/json"
	"net"
	"sync"
	"testing"

	pb "cast-receiver/castpb"
)

func TestSourceIDForNamespaceUsesAppTransportForMedia(t *testing.T) {
	if got := sourceIDForNamespace(nsMedia); got != defaultTransport {
		t.Fatalf("sourceIDForNamespace(nsMedia) = %q, want %q", got, defaultTransport)
	}
}

func TestSourceIDForNamespaceUsesReceiverForReceiverNamespaces(t *testing.T) {
	for _, ns := range []string{nsReceiver, nsHeartbeat, nsConnection} {
		t.Run(ns, func(t *testing.T) {
			if got := sourceIDForNamespace(ns); got != defaultReceiverID {
				t.Fatalf("sourceIDForNamespace(%q) = %q, want %q", ns, got, defaultReceiverID)
			}
		})
	}
}

// appendConn is a test double for the underlying Session connection. It embeds
// a nil net.Conn so only Write is needed by Send; it records every write so
// tests can inspect the serialized CastMessages.
type appendConn struct {
	net.Conn
	mu     sync.Mutex
	chunks [][]byte
}

func (c *appendConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := append([]byte(nil), p...)
	c.chunks = append(c.chunks, cp)
	return len(p), nil
}

func (c *appendConn) messages() []*pb.CastMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	var buf bytes.Buffer
	for _, chunk := range c.chunks {
		buf.Write(chunk)
	}
	var out []*pb.CastMessage
	for buf.Len() > 0 {
		msg, err := ReadMessage(&buf)
		if err != nil {
			break
		}
		out = append(out, msg)
	}
	return out
}

func TestSessionSendRoutesMediaViaDefaultTransport(t *testing.T) {
	conn := &appendConn{}
	s := &Session{conn: conn}

	s.send("sender-123", nsMedia, json.RawMessage(`{"type":"MEDIA_STATUS"}`))
	s.send("sender-123", nsReceiver, json.RawMessage(`{"type":"RECEIVER_STATUS"}`))

	msgs := conn.messages()
	if len(msgs) != 2 {
		t.Fatalf("len(messages) = %d, want 2", len(msgs))
	}

	media := msgs[0]
	if got := media.GetNamespace(); got != nsMedia {
		t.Fatalf("send(nsMedia) namespace = %q, want %q", got, nsMedia)
	}
	if got := media.GetSourceId(); got != defaultTransport {
		t.Fatalf("send(nsMedia) sourceID = %q, want %q", got, defaultTransport)
	}
	if got := media.GetDestinationId(); got != "sender-123" {
		t.Fatalf("send(nsMedia) destination = %q, want %q", got, "sender-123")
	}

	receiverStatus := msgs[1]
	if got := receiverStatus.GetNamespace(); got != nsReceiver {
		t.Fatalf("send(nsReceiver) namespace = %q, want %q", got, nsReceiver)
	}
	if got := receiverStatus.GetSourceId(); got != defaultReceiverID {
		t.Fatalf("send(nsReceiver) sourceID = %q, want %q", got, defaultReceiverID)
	}
	if got := receiverStatus.GetDestinationId(); got != "sender-123" {
		t.Fatalf("send(nsReceiver) destination = %q, want %q", got, "sender-123")
	}
}

func TestSessionSendRawUsesRememberedSenderDestination(t *testing.T) {
	conn := &appendConn{}
	s := &Session{conn: conn}

	appSenderID := "sender-456"
	s.rememberSender(appSenderID)
	if got := s.senderDestination(); got != appSenderID {
		t.Fatalf("senderDestination() = %q, want %q", got, appSenderID)
	}

	s.sendRaw(nsMedia, json.RawMessage(`{"type":"CUSTOM"}`))

	msgs := conn.messages()
	if len(msgs) != 1 {
		t.Fatalf("len(messages) = %d, want 1", len(msgs))
	}
	msg := msgs[0]
	if got := msg.GetNamespace(); got != nsMedia {
		t.Fatalf("sendRaw(nsMedia) namespace = %q, want %q", got, nsMedia)
	}
	if got := msg.GetSourceId(); got != defaultTransport {
		t.Fatalf("sendRaw(nsMedia) sourceID = %q, want %q", got, defaultTransport)
	}
	if got := msg.GetDestinationId(); got != appSenderID {
		t.Fatalf("sendRaw(nsMedia) destination = %q, want %q", got, appSenderID)
	}
}

func TestSessionSendRawDefaultsToBroadcastDestination(t *testing.T) {
	conn := &appendConn{}
	s := &Session{conn: conn}

	s.sendRaw(nsReceiver, json.RawMessage(`{"type":"STATUS"}`))

	msgs := conn.messages()
	if len(msgs) != 1 {
		t.Fatalf("len(messages) = %d, want 1", len(msgs))
	}
	msg := msgs[0]
	if got := msg.GetDestinationId(); got != "*" {
		t.Fatalf("sendRaw(nsReceiver) destination = %q, want *", got)
	}
	if got := msg.GetSourceId(); got != defaultReceiverID {
		t.Fatalf("sendRaw(nsReceiver) sourceID = %q, want %q", got, defaultReceiverID)
	}
}
