package cast

import (
	"encoding/json"
	"log"
	"net"
	"sync"

	pb "cast-receiver/castpb"

	"google.golang.org/protobuf/proto"
)

const (
	nsConnection = "urn:x-cast:com.google.cast.tp.connection"
	nsHeartbeat  = "urn:x-cast:com.google.cast.tp.heartbeat"
	nsReceiver   = "urn:x-cast:com.google.cast.receiver"
	nsDeviceAuth = "urn:x-cast:com.google.cast.tp.deviceauth"

	defaultReceiverID = "receiver-0"
	defaultAppID      = "CC1AD845"
	defaultTransport  = "web-1"
)

// Session holds state for one connected Cast sender.
type Session struct {
	conn     net.Conn
	mu       sync.Mutex
	receiver *Receiver
	sourceID string
	senderID string
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
func HandleConnection(conn net.Conn, receiver *Receiver) {
	if handshakeConn, ok := conn.(interface{ Handshake() error }); ok {
		if err := handshakeConn.Handshake(); err != nil {
			log.Printf("session: handshake error from %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			return
		}
	}

	s := &Session{
		conn:     conn,
		receiver: receiver,
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
	dest := msg.GetDestinationId()
	s.rememberSender(src)

	if msg.GetPayloadType() == pb.CastMessage_STRING {
		log.Printf("session[%s]: recv %s %s->%s %s", s.sourceID, ns, src, dest, msg.GetPayloadUtf8())
	} else {
		log.Printf("session[%s]: recv %s %s->%s binary(%d)", s.sourceID, ns, src, dest, len(msg.GetPayloadBinary()))
	}

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
			handleMediaMessage(s, src, json.RawMessage(msg.GetPayloadUtf8()))
		}
	default:
		log.Printf("session[%s]: unknown namespace %q from %s", s.sourceID, ns, src)
	}
}

func (s *Session) rememberSender(src string) {
	if src == "" || src == defaultReceiverID {
		return
	}
	s.mu.Lock()
	s.senderID = src
	s.mu.Unlock()
}

func (s *Session) senderDestination() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.senderID == "" {
		return "*"
	}
	return s.senderID
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
		if msg.GetDestinationId() == defaultTransport {
			s.receiver.CloseApp()
		}
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
		resp := receiverStatusMessage(s.receiver, req.RequestID)
		b, _ := json.Marshal(resp)
		s.send(src, nsReceiver, b)

	case "LAUNCH":
		appID := req.AppID
		log.Printf("session[%s]: LAUNCH %s", s.sourceID, appID)
		apps := s.receiver.LaunchApp(appID)
		status := receiverStatusPayload(s.receiver)
		if len(apps) > 0 {
			status["applications"] = apps
		} else {
			status["applications"] = []AppStatus{}
		}
		resp := map[string]interface{}{
			"requestId": req.RequestID,
			"status":    status,
			"type":      "RECEIVER_STATUS",
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
		vol := s.receiver.Volume()
		if volReq.Volume.Level != nil {
			vol.Level = *volReq.Volume.Level
		}
		if volReq.Volume.Muted != nil {
			vol.Muted = *volReq.Volume.Muted
		}
		s.receiver.SetVolume(vol)
		resp := receiverStatusMessage(s.receiver, req.RequestID)
		b, _ := json.Marshal(resp)
		s.send(src, nsReceiver, b)

	default:
		log.Printf("session[%s]: receiver unknown type %q", s.sourceID, req.Type)
	}
}

func receiverStatusMessage(r *Receiver, reqID int) map[string]interface{} {
	return map[string]interface{}{
		"requestId": reqID,
		"status":    receiverStatusPayload(r),
		"type":      "RECEIVER_STATUS",
	}
}

func receiverStatusPayload(r *Receiver) map[string]interface{} {
	vol := r.Volume()
	return map[string]interface{}{
		"applications":  r.AppStatus(),
		"isActiveInput": true,
		"isStandBy":     false,
		"volume": map[string]interface{}{
			"controlType": "attenuation",
			"level":       vol.Level,
			"muted":       vol.Muted,
		},
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
		SourceId:        proto.String(defaultReceiverID),
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
	log.Printf("session[%s]: send %s %s->%s binary(%d)", s.sourceID, nsDeviceAuth, defaultReceiverID, src, len(b))
	WriteMessage(s.conn, resp)
}

func (s *Session) send(dest, ns string, payload json.RawMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sourceID := sourceIDForNamespace(ns)
	msg := &pb.CastMessage{
		ProtocolVersion: pb.CastMessage_CASTV2_1_0.Enum(),
		SourceId:        proto.String(sourceID),
		DestinationId:   proto.String(dest),
		Namespace:       proto.String(ns),
		PayloadType:     pb.CastMessage_STRING.Enum(),
		PayloadUtf8:     proto.String(string(payload)),
	}
	log.Printf("session[%s]: send %s %s->%s %s", s.sourceID, ns, sourceID, dest, payload)
	if err := WriteMessage(s.conn, msg); err != nil {
		log.Printf("session[%s]: send error: %v", s.sourceID, err)
	}
}

// sendRaw writes a raw CastMessage to this session's connection (no lock).
func (s *Session) sendRaw(ns string, payload json.RawMessage) {
	s.send(s.senderDestination(), ns, payload)
}

func sourceIDForNamespace(ns string) string {
	if ns == nsMedia {
		return defaultTransport
	}
	return defaultReceiverID
}
