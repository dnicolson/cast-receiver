package cast

import (
	"encoding/json"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const nsMedia = "urn:x-cast:com.google.cast.media"

// MediaSession tracks one active media playback session.
type MediaSession struct {
	mu           sync.Mutex
	SessionID    int    `json:"sessionId"`
	Media        *MediaInfo
	PlayerState  string  `json:"playerState"`  // IDLE, PLAYING, PAUSED, BUFFERING
	IdleReason   string  `json:"idleReason,omitempty"`
	CurrentTime  float64 `json:"currentTime"`
	Volume       Volume  `json:"volume"`
	ActiveTrackIDs []int `json:"activeTrackIds,omitempty"`

	// playback control
	cmd    *exec.Cmd
	stdin  ioWriteCloser
	cancel func()
}

// MediaInfo is a minimal representation of loaded media.
type MediaInfo struct {
	ContentID   string `json:"contentId"`
	ContentType string `json:"contentType"`
	StreamType  string `json:"streamType"`
	Duration    float64    `json:"duration,omitempty"`
	Metadata    *Metadata  `json:"metadata,omitempty"`
}

type Metadata struct {
	Title  string `json:"title,omitempty"`
	Images []Image `json:"images,omitempty"`
}

type Image struct {
	URL string `json:"url"`
}

type Volume struct {
	Level float64 `json:"level"`
	Muted bool    `json:"muted"`
}

// nsMediaHandler handles the urn:x-cast:com.google.cast.media namespace.
type nsMediaHandler struct {
	session  *MediaSession
	sendMsg  func(dest string, payload json.RawMessage)
}

type ioWriteCloser interface {
	Write([]byte) (int, error)
	Close() error
}

func newMediaHandler(sendMsg func(string, json.RawMessage)) *nsMediaHandler {
	return &nsMediaHandler{
		session: &MediaSession{
			SessionID:   rand.Int(),
			PlayerState: "IDLE",
			Volume:      Volume{Level: 1, Muted: false},
		},
		sendMsg: sendMsg,
	}
}

type mediaRequest struct {
	Type      string     `json:"type"`
	RequestID int        `json:"requestId"`
	Media     *MediaInfo `json:"media,omitempty"`
	SessionID int        `json:"sessionId,omitempty"`
}

type mediaStatusMsg struct {
	Type      string         `json:"type"`
	RequestID int            `json:"requestId"`
	Status    []*MediaSession `json:"status"`
}

func (h *nsMediaHandler) Handle(src string, body json.RawMessage) {
	var req mediaRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("media: bad request: %v", err)
		return
	}
	switch req.Type {
	case "LOAD":
		h.handleLoad(src, &req)
	case "PLAY":
		h.handlePlay(src, &req)
	case "PAUSE":
		h.handlePause(src, &req)
	case "STOP":
		h.handleStop(src, &req)
	case "GET_STATUS":
		h.sendStatus(src, req.RequestID)
	default:
		log.Printf("media: unknown type %q", req.Type)
	}
}

func (h *nsMediaHandler) handleLoad(src string, req *mediaRequest) {
	h.session.mu.Lock()
	h.session.Media = req.Media
	h.session.PlayerState = "BUFFERING"
	h.session.mu.Unlock()

	contentID := ""
	contentType := "video/mp4"
	if req.Media != nil {
		contentID = req.Media.ContentID
		contentType = req.Media.ContentType
	}

	// If it's a local file, try to start ffplay for audio playback
	// (ponytail: ffplay for now; proper http range streaming if needed)
	if contentID != "" && contentType != "" {
		go h.playMedia(contentID)
	}

	// Wait a moment then mark as playing
	// ponytail: hardcoded BUFFERING->PLAYING; real buffering state management if needed
	time.Sleep(500 * time.Millisecond)
	h.session.mu.Lock()
	h.session.PlayerState = "PLAYING"
	h.session.mu.Unlock()

	h.sendStatus(src, req.RequestID)
}

func (h *nsMediaHandler) playMedia(path string) {
	// If it's a URL, we don't know how to play it - just log
	// ponytail: local file playback only; add URL streaming with ffmpeg pipe if needed
	if path != "" && path[0] != '/' {
		log.Printf("media: remote URL %q — no playback, just acknowledging", path)
		return
	}

	// Check file exists
	absPath, err := filepath.Abs(path)
	if err != nil {
		log.Printf("media: bad path %q: %v", path, err)
		return
	}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		log.Printf("media: file not found: %s", absPath)
		return
	}

	log.Printf("media: playing %s", absPath)

	// Use ffplay in a new process group so we can kill it
	// ponytail: exec'd ffplay; embed a player with go-mpv if we need more control
	cmd := exec.Command("ffplay", "-nodisp", "-autoexit", absPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	h.session.mu.Lock()
	h.session.cmd = cmd
	h.session.mu.Unlock()
	if err := cmd.Run(); err != nil {
		log.Printf("media: ffplay exited: %v", err)
	}
	h.session.mu.Lock()
	h.session.PlayerState = "IDLE"
	h.session.mu.Unlock()
}

func (h *nsMediaHandler) handlePlay(src string, req *mediaRequest) {
	h.session.mu.Lock()
	h.session.PlayerState = "PLAYING"
	h.session.mu.Unlock()
	h.sendStatus(src, req.RequestID)
}

func (h *nsMediaHandler) handlePause(src string, req *mediaRequest) {
	h.session.mu.Lock()
	h.session.PlayerState = "PAUSED"
	h.session.mu.Unlock()
	// ponytail: no actual ffplay pause (ffplay has no stdin control); add proper IPC if pausing matters
	h.sendStatus(src, req.RequestID)
}

func (h *nsMediaHandler) handleStop(src string, req *mediaRequest) {
	h.session.mu.Lock()
	h.session.PlayerState = "IDLE"
	h.session.IdleReason = "CANCELLED"
	if h.session.cmd != nil && h.session.cmd.Process != nil {
		h.session.cmd.Process.Kill()
	}
	h.session.cmd = nil
	h.session.mu.Unlock()
	h.sendStatus(src, req.RequestID)
}

func (h *nsMediaHandler) sendStatus(src string, reqID int) {
	h.session.mu.Lock()
	status := *h.session
	h.session.mu.Unlock()

	msg := mediaStatusMsg{
		Type:      "MEDIA_STATUS",
		RequestID: reqID,
		Status:    []*MediaSession{&status},
	}
	b, _ := json.Marshal(msg)
	h.sendMsg(src, json.RawMessage(b))
}


