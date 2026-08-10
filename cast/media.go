package cast

import (
	"encoding/json"
	"log"
	"strings"
	"sync"
)

const nsMedia = "urn:x-cast:com.google.cast.media"

const (
	playerStateIdle    = "IDLE"
	playerStatePlaying = "PLAYING"
	playerStatePaused  = "PAUSED"

	idleReasonCancelled = "CANCELLED"

	mediaCommandPause        = 1 << 0
	mediaCommandSeek         = 1 << 1
	mediaCommandStreamVolume = 1 << 2
	mediaCommandStreamMute   = 1 << 3

	supportedMediaCommands = mediaCommandPause | mediaCommandSeek | mediaCommandStreamVolume | mediaCommandStreamMute
)

// MediaSession tracks media playback state shared across all senders.
type MediaSession struct {
	mu                     sync.Mutex
	MediaSessionID         int             `json:"mediaSessionId,omitempty"`
	Media                  *MediaInfo      `json:"media,omitempty"`
	PlayerState            string          `json:"playerState"`
	IdleReason             string          `json:"idleReason,omitempty"`
	CurrentTime            float64         `json:"currentTime"`
	PlaybackRate           float64         `json:"playbackRate"`
	SupportedMediaCommands int             `json:"supportedMediaCommands,omitempty"`
	Volume                 Volume          `json:"volume"`
	ActiveTrackIDs         []int           `json:"activeTrackIds,omitempty"`
	CustomData             json.RawMessage `json:"customData,omitempty"`
}

type MediaInfo struct {
	ContentID   string          `json:"contentId"`
	ContentType string          `json:"contentType"`
	StreamType  string          `json:"streamType,omitempty"`
	Duration    float64         `json:"duration,omitempty"`
	Metadata    *Metadata       `json:"metadata,omitempty"`
	CustomData  json.RawMessage `json:"customData,omitempty"`
}

type Metadata struct {
	MetadataType *int    `json:"metadataType,omitempty"`
	Title        string  `json:"title,omitempty"`
	Subtitle     string  `json:"subtitle,omitempty"`
	Images       []Image `json:"images,omitempty"`
	ReleaseDate  string  `json:"releaseDate,omitempty"`
}

type Image struct {
	URL    string `json:"url"`
	Height int    `json:"height,omitempty"`
	Width  int    `json:"width,omitempty"`
}

type Volume struct {
	Level float64 `json:"level"`
	Muted bool    `json:"muted"`
}

type mediaRequest struct {
	Type           string          `json:"type"`
	RequestID      int             `json:"requestId"`
	Media          *MediaInfo      `json:"media,omitempty"`
	MediaSessionID int             `json:"mediaSessionId,omitempty"`
	Autoplay       json.RawMessage `json:"autoplay,omitempty"`
	CurrentTime    *float64        `json:"currentTime,omitempty"`
	ResumeState    string          `json:"resumeState,omitempty"`
	Volume         *volumePatch    `json:"volume,omitempty"`
	CustomData     json.RawMessage `json:"customData,omitempty"`
}

type mediaStatusMsg struct {
	Type       string          `json:"type"`
	RequestID  int             `json:"requestId"`
	Status     []*MediaSession `json:"status"`
	CustomData json.RawMessage `json:"customData,omitempty"`
}

type mediaErrorMsg struct {
	Type       string          `json:"type"`
	RequestID  int             `json:"requestId"`
	Reason     string          `json:"reason,omitempty"`
	CustomData json.RawMessage `json:"customData,omitempty"`
}

type volumePatch struct {
	Level *float64 `json:"level,omitempty"`
	Muted *bool    `json:"muted,omitempty"`
}

// handleMediaMessage routes media namespace commands using the Receiver's shared state.
func handleMediaMessage(s *Session, src string, body json.RawMessage) {
	var req mediaRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("media: bad request: %v", err)
		sendMediaError(s, src, 0, "INVALID_REQUEST", "INVALID_COMMAND")
		return
	}
	switch req.Type {
	case "LOAD":
		handleLoad(s, src, &req)
	case "PLAY":
		handlePlay(s, src, &req)
	case "PAUSE":
		handlePause(s, src, &req)
	case "STOP":
		handleStop(s, src, &req)
	case "SEEK":
		handleSeek(s, src, &req)
	case "GET_STATUS":
		sendMediaStatus(s, src, req.RequestID, req.MediaSessionID, false)
	case "VOLUME", "SET_VOLUME":
		handleMediaVolume(s, src, &req)
	default:
		log.Printf("media: unknown type %q", req.Type)
		sendMediaError(s, src, req.RequestID, "INVALID_REQUEST", "INVALID_COMMAND")
	}
}

func handleLoad(s *Session, src string, req *mediaRequest) {
	r := s.receiver

	if req.Media == nil || req.Media.ContentID == "" {
		sendMediaError(s, src, req.RequestID, "LOAD_FAILED", "")
		return
	}

	currentTime := 0.0
	if req.CurrentTime != nil && *req.CurrentTime > 0 {
		currentTime = *req.CurrentTime
	}
	playerState := initialPlayerStateForLoad(req)
	mediaSessionID := r.NextMediaSessionID()
	r.Media.mu.Lock()
	r.Media.MediaSessionID = mediaSessionID
	r.Media.Media = req.Media
	r.Media.PlayerState = playerState
	r.Media.IdleReason = ""
	r.Media.CurrentTime = currentTime
	r.Media.PlaybackRate = playbackRateForState(playerState)
	r.Media.SupportedMediaCommands = supportedMediaCommands
	r.Media.CustomData = req.CustomData
	r.Media.mu.Unlock()

	sendMediaStatus(s, src, req.RequestID, 0, true)
}

func handlePlay(s *Session, src string, req *mediaRequest) {
	r := s.receiver
	if !validMediaSession(r, req.MediaSessionID) {
		sendMediaError(s, src, req.RequestID, "INVALID_PLAYER_STATE", "")
		return
	}
	r.Media.mu.Lock()
	r.Media.PlayerState = playerStatePlaying
	r.Media.IdleReason = ""
	r.Media.PlaybackRate = playbackRateForState(playerStatePlaying)
	r.Media.mu.Unlock()
	sendMediaStatus(s, src, req.RequestID, 0, true)
}

func handlePause(s *Session, src string, req *mediaRequest) {
	r := s.receiver
	if !validMediaSession(r, req.MediaSessionID) {
		sendMediaError(s, src, req.RequestID, "INVALID_PLAYER_STATE", "")
		return
	}
	r.Media.mu.Lock()
	r.Media.PlayerState = playerStatePaused
	r.Media.PlaybackRate = playbackRateForState(playerStatePaused)
	r.Media.mu.Unlock()
	sendMediaStatus(s, src, req.RequestID, 0, true)
}

func handleStop(s *Session, src string, req *mediaRequest) {
	r := s.receiver
	if !validMediaSession(r, req.MediaSessionID) {
		sendMediaError(s, src, req.RequestID, "INVALID_PLAYER_STATE", "")
		return
	}
	r.Media.mu.Lock()
	r.Media.MediaSessionID = 0
	r.Media.Media = nil
	r.Media.PlayerState = playerStateIdle
	r.Media.IdleReason = idleReasonCancelled
	r.Media.CurrentTime = 0
	r.Media.PlaybackRate = playbackRateForState(playerStateIdle)
	r.Media.SupportedMediaCommands = 0
	r.Media.CustomData = nil
	r.Media.mu.Unlock()
	sendMediaStatus(s, src, req.RequestID, 0, true)
}

func handleSeek(s *Session, src string, req *mediaRequest) {
	r := s.receiver
	if !validMediaSession(r, req.MediaSessionID) {
		sendMediaError(s, src, req.RequestID, "INVALID_PLAYER_STATE", "")
		return
	}

	r.Media.mu.Lock()
	if req.CurrentTime != nil {
		r.Media.CurrentTime = clampMediaTime(*req.CurrentTime, r.Media.Media)
	}
	switch req.ResumeState {
	case "PLAYBACK_START":
		r.Media.PlayerState = playerStatePlaying
		r.Media.IdleReason = ""
	case "PLAYBACK_PAUSE":
		r.Media.PlayerState = playerStatePaused
	}
	r.Media.PlaybackRate = playbackRateForState(r.Media.PlayerState)
	r.Media.mu.Unlock()

	sendMediaStatus(s, src, req.RequestID, 0, true)
}

func handleMediaVolume(s *Session, src string, req *mediaRequest) {
	r := s.receiver
	if !validMediaSession(r, req.MediaSessionID) {
		sendMediaError(s, src, req.RequestID, "INVALID_PLAYER_STATE", "")
		return
	}
	if req.Volume == nil || (req.Volume.Level == nil && req.Volume.Muted == nil) {
		sendMediaError(s, src, req.RequestID, "INVALID_REQUEST", "INVALID_COMMAND")
		return
	}
	r.Media.mu.Lock()
	vol := r.Media.Volume
	if req.Volume.Level != nil {
		vol.Level = clampVolume(*req.Volume.Level)
	}
	if req.Volume.Muted != nil {
		vol.Muted = *req.Volume.Muted
	}
	r.Media.Volume = vol
	r.Media.mu.Unlock()
	sendMediaStatus(s, src, req.RequestID, 0, true)
}

func sendMediaStatus(s *Session, src string, reqID int, mediaSessionID int, broadcast bool) {
	msg := buildMediaStatus(s.receiver, reqID, mediaSessionID)
	b, _ := json.Marshal(msg)
	payload := json.RawMessage(b)
	s.send(src, nsMedia, payload)
	if broadcast {
		s.receiver.Broadcast(s.sourceID, nsMedia, payload)
	}
}

// BroadcastMediaStatus sends an unsolicited status update to connected senders.
func (r *Receiver) BroadcastMediaStatus(reqID int) {
	msg := buildMediaStatus(r, reqID, 0)
	b, _ := json.Marshal(msg)
	r.Broadcast("", nsMedia, json.RawMessage(b))
}

func sendMediaError(s *Session, src string, reqID int, errorType string, reason string) {
	msg := mediaErrorMsg{
		Type:      errorType,
		RequestID: reqID,
		Reason:    reason,
	}
	b, _ := json.Marshal(msg)
	s.send(src, nsMedia, json.RawMessage(b))
}

func buildMediaStatus(r *Receiver, reqID int, mediaSessionID int) mediaStatusMsg {
	r.Media.mu.Lock()
	sid := r.Media.MediaSessionID
	ps := r.Media.PlayerState
	ir := r.Media.IdleReason
	media := r.Media.Media
	vol := r.Media.Volume
	currentTime := r.Media.CurrentTime
	playbackRate := r.Media.PlaybackRate
	commands := r.Media.SupportedMediaCommands
	customData := cloneRawMessage(r.Media.CustomData)
	r.Media.mu.Unlock()

	msg := mediaStatusMsg{
		Type:      "MEDIA_STATUS",
		RequestID: reqID,
		Status:    []*MediaSession{},
	}
	if mediaSessionID != 0 && mediaSessionID != sid {
		return msg
	}
	if sid != 0 || ps != playerStateIdle {
		msg.Status = append(msg.Status, &MediaSession{
			MediaSessionID:         sid,
			PlayerState:            ps,
			IdleReason:             idleReasonForState(ps, ir),
			Media:                  media,
			Volume:                 vol,
			CurrentTime:            currentTime,
			PlaybackRate:           playbackRate,
			SupportedMediaCommands: commands,
			CustomData:             customData,
		})
	}
	return msg
}

func (r *mediaRequest) AutoplayEnabled() bool {
	if len(r.Autoplay) == 0 {
		return true
	}

	var b bool
	if err := json.Unmarshal(r.Autoplay, &b); err == nil {
		return b
	}

	var s string
	if err := json.Unmarshal(r.Autoplay, &s); err == nil {
		return s != "" && s != "0" && s != "false"
	}

	var n float64
	if err := json.Unmarshal(r.Autoplay, &n); err == nil {
		return n != 0
	}

	return true
}

func initialPlayerStateForLoad(req *mediaRequest) string {
	if !req.AutoplayEnabled() {
		return playerStatePaused
	}
	return playerStatePlaying
}

func normalizeHTTPMediaURL(source string) string {
	schemeEnd := strings.Index(source, "://")
	if schemeEnd < 0 {
		return source
	}
	hostStart := schemeEnd + len("://")
	if hostStart >= len(source) || source[hostStart] != '[' {
		return source
	}
	hostEndOffset := strings.IndexByte(source[hostStart:], ']')
	if hostEndOffset < 0 {
		return source
	}
	hostEnd := hostStart + hostEndOffset
	host := source[hostStart+1 : hostEnd]
	zoneStart := strings.IndexByte(host, '%')
	if zoneStart < 0 {
		return source
	}
	if len(host[zoneStart:]) >= 3 && strings.EqualFold(host[zoneStart:zoneStart+3], "%25") {
		return source
	}

	escapedHost := host[:zoneStart] + "%25" + host[zoneStart+1:]
	return source[:hostStart+1] + escapedHost + source[hostEnd:]
}

func validMediaSession(r *Receiver, mediaSessionID int) bool {
	r.Media.mu.Lock()
	defer r.Media.mu.Unlock()
	if r.Media.MediaSessionID == 0 || r.Media.Media == nil {
		return false
	}
	return mediaSessionID == 0 || mediaSessionID == r.Media.MediaSessionID
}

func clampVolume(level float64) float64 {
	if level < 0 {
		return 0
	}
	if level > 1 {
		return 1
	}
	return level
}

func clampMediaTime(currentTime float64, media *MediaInfo) float64 {
	if currentTime < 0 {
		return 0
	}
	if media != nil && media.Duration > 0 && currentTime > media.Duration {
		return media.Duration
	}
	return currentTime
}

func playbackRateForState(playerState string) float64 {
	if playerState == playerStatePlaying {
		return 1
	}
	return 0
}

func idleReasonForState(playerState string, idleReason string) string {
	if playerState == playerStateIdle {
		return idleReason
	}
	return ""
}

func cloneRawMessage(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}
