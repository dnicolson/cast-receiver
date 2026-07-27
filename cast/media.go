package cast

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const nsMedia = "urn:x-cast:com.google.cast.media"

// MediaSession tracks media playback state shared across all senders.
type MediaSession struct {
	mu             sync.Mutex
	SessionID      int        `json:"sessionId"`
	Media          *MediaInfo `json:"media,omitempty"`
	PlayerState    string     `json:"playerState"`
	IdleReason     string     `json:"idleReason,omitempty"`
	CurrentTime    float64    `json:"currentTime"`
	Volume         Volume     `json:"volume"`
	ActiveTrackIDs []int      `json:"activeTrackIds,omitempty"`

	cmd       *exec.Cmd
	stopProxy func()
}

type MediaInfo struct {
	ContentID   string    `json:"contentId"`
	ContentType string    `json:"contentType"`
	StreamType  string    `json:"streamType,omitempty"`
	Duration    float64   `json:"duration,omitempty"`
	Metadata    *Metadata `json:"metadata,omitempty"`
}

type Metadata struct {
	Title  string  `json:"title,omitempty"`
	Images []Image `json:"images,omitempty"`
}

type Image struct {
	URL string `json:"url"`
}

type Volume struct {
	Level float64 `json:"level"`
	Muted bool    `json:"muted"`
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

// handleMediaMessage routes media namespace commands using the Receiver's shared state.
func handleMediaMessage(r *Receiver, src string, body json.RawMessage) {
	var req mediaRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("media: bad request: %v", err)
		return
	}
	switch req.Type {
	case "LOAD":
		handleLoad(r, src, &req)
	case "PLAY":
		handlePlay(r, src, &req)
	case "PAUSE":
		handlePause(r, src, &req)
	case "STOP":
		handleStop(r, src, &req)
	case "GET_STATUS":
		sendMediaStatus(r, src, req.RequestID)
	default:
		log.Printf("media: unknown type %q", req.Type)
	}
}

func handleLoad(r *Receiver, src string, req *mediaRequest) {
	r.Media.mu.Lock()
	r.Media.Media = req.Media
	r.Media.PlayerState = "BUFFERING"
	r.Media.mu.Unlock()

	contentID := ""
	
	if req.Media != nil {
		contentID = req.Media.ContentID
		
	}

	if contentID == "" {
		sendMediaStatus(r, src, req.RequestID)
		return
	}

	if strings.Contains(contentID, "://") {
		handleRemoteURL(r, contentID)
	} else {
		go playLocalFile(r, contentID)
	}

	time.Sleep(500 * time.Millisecond)
	r.Media.mu.Lock()
	r.Media.PlayerState = "PLAYING"
	r.Media.mu.Unlock()
	sendMediaStatus(r, src, req.RequestID)
}

func handleRemoteURL(r *Receiver, url string) {
	log.Printf("media: proxying remote URL %s", url)

	port, stop := StartProxy(url)
	if port == 0 {
		log.Printf("media: failed to start proxy for %s", url)
		return
	}

	r.Media.mu.Lock()
	r.Media.stopProxy = stop
	if r.Media.Media != nil {
		r.Media.Media.ContentID = fmt.Sprintf("http://127.0.0.1:%d/stream", port)
	}
	r.Media.mu.Unlock()

	go func() {
		cmd := exec.Command("ffplay", "-nodisp", "-autoexit", fmt.Sprintf("http://127.0.0.1:%d/stream", port))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		r.Media.mu.Lock()
		r.Media.cmd = cmd
		r.Media.mu.Unlock()
		if err := cmd.Run(); err != nil {
			log.Printf("media: ffplay exited: %v", err)
		}
		r.Media.mu.Lock()
		r.Media.PlayerState = "IDLE"
		r.Media.mu.Unlock()
	}()
}

func playLocalFile(r *Receiver, path string) {
	if path[0] != '/' {
		log.Printf("media: remote URL %q — can't play", path)
		return
	}
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

	cmd := exec.Command("ffplay", "-nodisp", "-autoexit", absPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	r.Media.mu.Lock()
	r.Media.cmd = cmd
	r.Media.mu.Unlock()
	if err := cmd.Run(); err != nil {
		log.Printf("media: ffplay exited: %v", err)
	}
	r.Media.mu.Lock()
	r.Media.PlayerState = "IDLE"
	r.Media.mu.Unlock()
}

func handlePlay(r *Receiver, src string, req *mediaRequest) {
	r.Media.mu.Lock()
	r.Media.PlayerState = "PLAYING"
	r.Media.mu.Unlock()
	sendMediaStatus(r, src, req.RequestID)
}

func handlePause(r *Receiver, src string, req *mediaRequest) {
	r.Media.mu.Lock()
	r.Media.PlayerState = "PAUSED"
	r.Media.mu.Unlock()
	sendMediaStatus(r, src, req.RequestID)
}

func handleStop(r *Receiver, src string, req *mediaRequest) {
	r.Media.mu.Lock()
	r.Media.PlayerState = "IDLE"
	r.Media.IdleReason = "CANCELLED"
	if r.Media.cmd != nil && r.Media.cmd.Process != nil {
		r.Media.cmd.Process.Kill()
	}
	r.Media.cmd = nil
	if r.Media.stopProxy != nil {
		r.Media.stopProxy()
		r.Media.stopProxy = nil
	}
	r.Media.mu.Unlock()
	sendMediaStatus(r, src, req.RequestID)
}

func sendMediaStatus(r *Receiver, src string, reqID int) {
	r.Media.mu.Lock()
	sid := r.Media.SessionID
	ps := r.Media.PlayerState
	ir := r.Media.IdleReason
	media := r.Media.Media
	vol := r.Media.Volume
	r.Media.mu.Unlock()

	msg := mediaStatusMsg{
		Type:      "MEDIA_STATUS",
		RequestID: reqID,
		Status: []*MediaSession{
			{SessionID: sid, PlayerState: ps, IdleReason: ir, Media: media, Volume: vol},
		},
	}
	b, _ := json.Marshal(msg)
	r.Broadcast(src, nsMedia, json.RawMessage(b))
}
