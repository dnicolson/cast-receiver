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
	conn  *tls.Conn
	mu    sync.Mutex
	media *nsMediaHandler

	apps []AppStatus
}

type AppStatus struct {
	AppID       string   `json:"appId"`
	DisplayName string   `json:"displayName"`
	Namespaces  []string `json:"namespaces"`
	SessionID   string   `json:"sessionId"`
	StatusText  string   `json:"statusText"`
	TransportID string   `json:"transportId"`
}

// HandleSession manages the full lifecycle of one TLS connection.
func HandleSession(conn *tls.Conn, friendlyName string) {
	s := &Session{
		conn: conn,
		apps: []AppStatus{{
			AppID:       "CC1AD845",
			DisplayName: "Default Media Receiver",
			Namespaces:  []string{nsMedia},
			SessionID:   "session-1",
			StatusText:  "Ready To Cast",
			TransportID: "web-1",
		}},
	}
	s.media = newMediaHandler(func(dest string, payload json.RawMessage) {
		s.send(dest, nsMedia, payload)
	})
	defer conn.Close()

	log.Printf("session: connected from %s", conn.RemoteAddr())

	for {
		msg, err := ReadMessage(conn)
		if err != nil {
			log.Printf("session: read error: %v", err)
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
			s.media.Handle(src, json.RawMessage(msg.GetPayloadUtf8()))
		}
	default:
		log.Printf("session: unknown namespace %q from %s", ns, src)
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
		log.Printf("connection: CONNECT from %s", src)
	case "CLOSE":
		log.Printf("connection: CLOSE from %s", src)
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
				"applications": s.apps,
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
		log.Printf("receiver: LAUNCH %s", req.AppID)
		// We auto-launch the Default Media Receiver for any app
		resp := map[string]interface{}{
			"requestId": req.RequestID,
			"status": map[string]interface{}{
				"applications": s.apps,
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
		log.Printf("receiver: SET_VOLUME level=%v muted=%v", volReq.Volume.Level, volReq.Volume.Muted)
		resp := map[string]interface{}{
			"requestId": req.RequestID,
			"type":      "RECEIVER_STATUS",
		}
		b, _ := json.Marshal(resp)
		s.send(src, nsReceiver, b)

	default:
		log.Printf("receiver: unknown type %q", req.Type)
	}
}

func (s *Session) handleDeviceAuth(src string, msg *pb.CastMessage) {
	log.Printf("deviceauth: challenge from %s", src)
	// ponytail: refuse auth; most senders skip the auth step or tolerate failure
	// Full auth requires Google's certificate chain which we don't have
	resp := &pb.CastMessage{
		ProtocolVersion: pb.CastMessage_CASTV2_1_0.Enum(),
		SourceId:        proto.String("receiver-0"),
		DestinationId:   proto.String(src),
		Namespace:       proto.String(nsDeviceAuth),
		PayloadType:     pb.CastMessage_BINARY.Enum(),
	}
	authMsg := &pb.DeviceAuthMessage{
		Error: &pb.AuthError{
			ErrorType: pb.AuthError_INTERNAL_ERROR.Enum(),
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
		log.Printf("send error: %v", err)
	}
}
