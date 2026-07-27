package cast

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"sync"

	pb "cast-receiver/castpb"

	"google.golang.org/protobuf/proto"
)

const (
	nsConnection = "urn:x-cast:com.google.cast.tp.connection"
	nsHeartbeat  = "urn:x-cast:com.google.cast.tp.heartbeat"
	nsReceiver   = "urn:x-cast:com.google.cast.receiver"
	nsDeviceAuth = "urn:x-cast:com.google.cast.tp.deviceauth"
)

// Session holds state for one connected Cast sender.
type Session struct {
	conn     *tls.Conn
	mu       sync.Mutex
	receiver *Receiver
	sourceID string
	apps     []AppStatus
}

type AppStatus struct {
	AppID       string   `json:"appId"`
	DisplayName string   `json:"displayName"`
	Namespaces  []string `json:"namespaces"`
	SessionID   string   `json:"sessionId"`
	StatusText  string   `json:"statusText"`
	TransportID string   `json:"transportId"`
}

// HandleConnection manages the full lifecycle of one TLS connection.
func HandleConnection(conn *tls.Conn, receiver *Receiver) {
	s := &Session{
		conn:     conn,
		receiver: receiver,
		apps: []AppStatus{{
			AppID:       "CC1AD845",
			DisplayName: "Default Media Receiver",
			Namespaces:  []string{nsMedia},
			SessionID:   "session-1",
			StatusText:  "Ready To Cast",
			TransportID: "web-1",
		}},
	}
	receiver.Register(s)
	defer func() {
		receiver.Unregister(s.sourceID)
		conn.Close()
	}()

	log.Printf("session: connected from %s as %s", conn.RemoteAddr(), s.sourceID)

	for {
		msg, err := ReadMessage(conn)
		if err != nil {
			log.Printf("session[%s]: read error: %v", s.sourceID, err)
			return
		}
		s.handleMessage(msg)
	}
}

func (s *Session) handleMessage(msg *pb.CastMessage) {
	ns := msg.GetNamespace()
	src := msg.GetSourceId()

	switch ns {
	case nsConnection:
		s.handleConnection(src, msg)
	case nsHeartbeat:
		s.handleHeartbeat(src, msg)
	case nsReceiver:
		s.handleReceiver(src, msg)
	case nsDeviceAuth:
		s.handleDeviceAuth(src, msg)
	case nsMedia:
		if msg.GetPayloadType() == pb.CastMessage_STRING {
			handleMediaMessage(s.receiver, src, json.RawMessage(msg.GetPayloadUtf8()))
		}
	default:
		log.Printf("session[%s]: unknown namespace %q from %s", s.sourceID, ns, src)
	}
}

func (s *Session) handleConnection(src string, msg *pb.CastMessage) {
	var c struct {
		Type string `json:"type"`
	}
	if msg.GetPayloadType() == pb.CastMessage_STRING {
		json.Unmarshal([]byte(msg.GetPayloadUtf8()), &c)
	}
	switch c.Type {
	case "CONNECT":
		log.Printf("session[%s]: CONNECT from %s", s.sourceID, src)
	case "CLOSE":
		log.Printf("session[%s]: CLOSE from %s", s.sourceID, src)
	}
}

func (s *Session) handleHeartbeat(src string, msg *pb.CastMessage) {
	var h struct {
		Type string `json:"type"`
	}
	if msg.GetPayloadType() == pb.CastMessage_STRING {
		json.Unmarshal([]byte(msg.GetPayloadUtf8()), &h)
	}
	if h.Type == "PING" {
		pong, _ := json.Marshal(map[string]string{"type": "PONG"})
		s.send(src, nsHeartbeat, pong)
	}
}

func (s *Session) handleReceiver(src string, msg *pb.CastMessage) {
	var req struct {
		Type      string `json:"type"`
		RequestID int    `json:"requestId"`
		AppID     string `json:"appId,omitempty"`
	}
	if msg.GetPayloadType() == pb.CastMessage_STRING {
		json.Unmarshal([]byte(msg.GetPayloadUtf8()), &req)
	}

	switch req.Type {
	case "GET_STATUS":
		resp := map[string]interface{}{
			"requestId": req.RequestID,
			"status": map[string]interface{}{
				"applications":  s.apps,
				"isActiveInput": true,
				"volume": map[string]interface{}{
					"level": 1.0,
					"muted": false,
				},
			},
			"type": "RECEIVER_STATUS",
		}
		b, _ := json.Marshal(resp)
		s.send(src, nsReceiver, b)

	case "LAUNCH":
		log.Printf("session[%s]: LAUNCH %s", s.sourceID, req.AppID)
		resp := map[string]interface{}{
			"requestId": req.RequestID,
			"status": map[string]interface{}{
				"applications":  s.apps,
				"isActiveInput": true,
				"volume": map[string]interface{}{
					"level": 1.0,
					"muted": false,
				},
			},
			"type": "RECEIVER_STATUS",
		}
		b, _ := json.Marshal(resp)
		s.send(src, nsReceiver, b)

	case "SET_VOLUME":
		var volReq struct {
			Volume struct {
				Level *float64 `json:"level,omitempty"`
				Muted *bool    `json:"muted,omitempty"`
			} `json:"volume"`
		}
		json.Unmarshal([]byte(msg.GetPayloadUtf8()), &volReq)
		log.Printf("session[%s]: SET_VOLUME", s.sourceID)
		resp := map[string]interface{}{
			"requestId": req.RequestID,
			"type":      "RECEIVER_STATUS",
		}
		b, _ := json.Marshal(resp)
		s.send(src, nsReceiver, b)

	default:
		log.Printf("session[%s]: receiver unknown type %q", s.sourceID, req.Type)
	}
}

func (s *Session) handleDeviceAuth(src string, msg *pb.CastMessage) {
	log.Printf("session[%s]: deviceauth challenge", s.sourceID)
	auth := s.receiver.Authenticator()
	sig, err := auth.SignTLS()
	if err != nil {
		log.Printf("session[%s]: sign error: %v", s.sourceID, err)
		return
	}

	resp := &pb.CastMessage{
		ProtocolVersion: pb.CastMessage_CASTV2_1_0.Enum(),
		SourceId:        proto.String("receiver-0"),
		DestinationId:   proto.String(src),
		Namespace:       proto.String(nsDeviceAuth),
		PayloadType:     pb.CastMessage_BINARY.Enum(),
	}
	authMsg := &pb.DeviceAuthMessage{
		Response: &pb.AuthResponse{
			Signature:             sig,
			ClientAuthCertificate: auth.AuthCertDER,
			ClientCa:              [][]byte{auth.AuthCertDER},
		},
	}
	b, _ := proto.Marshal(authMsg)
	resp.PayloadBinary = b
	WriteMessage(s.conn, resp)
}

func (s *Session) send(dest, ns string, payload json.RawMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	msg := &pb.CastMessage{
		ProtocolVersion: pb.CastMessage_CASTV2_1_0.Enum(),
		SourceId:        proto.String("receiver-0"),
		DestinationId:   proto.String(dest),
		Namespace:       proto.String(ns),
		PayloadType:     pb.CastMessage_STRING.Enum(),
		PayloadUtf8:     proto.String(string(payload)),
	}
	if err := WriteMessage(s.conn, msg); err != nil {
		log.Printf("session[%s]: send error: %v", s.sourceID, err)
	}
}

// sendRaw writes a raw CastMessage to this session's connection (no lock).
func (s *Session) sendRaw(ns string, payload json.RawMessage) {
	msg := &pb.CastMessage{
		ProtocolVersion: pb.CastMessage_CASTV2_1_0.Enum(),
		SourceId:        proto.String("receiver-0"),
		DestinationId:   proto.String(s.sourceID),
		Namespace:       proto.String(ns),
		PayloadType:     pb.CastMessage_STRING.Enum(),
		PayloadUtf8:     proto.String(string(payload)),
	}
	if err := WriteMessage(s.conn, msg); err != nil {
		log.Printf("session[%s]: sendRaw error: %v", s.sourceID, err)
	}
}
