package cast

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAutoplayEnabledAcceptsVLCStringBooleans(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "missing", want: true},
		{name: "bool false", raw: "false", want: false},
		{name: "bool true", raw: "true", want: true},
		{name: "string false", raw: `"false"`, want: false},
		{name: "string zero", raw: `"0"`, want: false},
		{name: "string true", raw: `"true"`, want: true},
		{name: "number zero", raw: "0", want: false},
		{name: "number one", raw: "1", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &mediaRequest{}
			if tt.raw != "" {
				req.Autoplay = json.RawMessage(tt.raw)
			}
			if got := req.AutoplayEnabled(); got != tt.want {
				t.Fatalf("AutoplayEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInitialPlayerStateForLoadHonorsAutoplay(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "missing autoplay starts playback", want: playerStatePlaying},
		{name: "autoplay true starts playback", raw: "true", want: playerStatePlaying},
		{name: "autoplay false pauses", raw: "false", want: playerStatePaused},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &mediaRequest{}
			if tt.raw != "" {
				req.Autoplay = json.RawMessage(tt.raw)
			}
			if got := initialPlayerStateForLoad(req); got != tt.want {
				t.Fatalf("initialPlayerStateForLoad() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildMediaStatusUsesMediaSessionID(t *testing.T) {
	r := NewReceiver(nil)
	r.Media.mu.Lock()
	r.Media.MediaSessionID = 7
	r.Media.PlayerState = "PAUSED"
	r.Media.Media = &MediaInfo{ContentID: "http://127.0.0.1:8010/stream", ContentType: "video/x-matroska"}
	r.Media.Volume = Volume{Level: 0.5}
	r.Media.mu.Unlock()

	msg := buildMediaStatus(r, 42, 0)
	if msg.Type != "MEDIA_STATUS" {
		t.Fatalf("Type = %q, want MEDIA_STATUS", msg.Type)
	}
	if msg.RequestID != 42 {
		t.Fatalf("RequestID = %d, want 42", msg.RequestID)
	}
	if len(msg.Status) != 1 {
		t.Fatalf("len(Status) = %d, want 1", len(msg.Status))
	}
	if got := msg.Status[0].MediaSessionID; got != 7 {
		t.Fatalf("MediaSessionID = %d, want 7", got)
	}

	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"mediaSessionId":7`) {
		t.Fatalf("status JSON missing mediaSessionId: %s", body)
	}
	if strings.Contains(string(body), `"sessionId":7`) {
		t.Fatalf("status JSON used legacy sessionId field: %s", body)
	}
}

func TestBuildMediaStatusFiltersByMediaSessionID(t *testing.T) {
	r := NewReceiver(nil)
	r.Media.mu.Lock()
	r.Media.MediaSessionID = 7
	r.Media.PlayerState = playerStatePaused
	r.Media.Media = &MediaInfo{ContentID: "http://127.0.0.1:8010/stream", ContentType: "video/mp4"}
	r.Media.mu.Unlock()

	msg := buildMediaStatus(r, 42, 8)
	if len(msg.Status) != 0 {
		t.Fatalf("len(Status) = %d, want 0 for mismatched mediaSessionId", len(msg.Status))
	}
}

func TestBuildMediaStatusIncludesBasicSpecFields(t *testing.T) {
	r := NewReceiver(nil)
	metadataType := 0
	r.Media.mu.Lock()
	r.Media.MediaSessionID = 7
	r.Media.PlayerState = playerStatePlaying
	r.Media.PlaybackRate = 1
	r.Media.SupportedMediaCommands = supportedMediaCommands
	r.Media.Media = &MediaInfo{
		ContentID:   "http://127.0.0.1:8010/stream",
		ContentType: "video/mp4",
		StreamType:  "BUFFERED",
		Duration:    52.209,
		Metadata:    &Metadata{MetadataType: &metadataType, Title: "Sintel Trailer"},
	}
	r.Media.Volume = Volume{Level: 0.5}
	r.Media.mu.Unlock()

	body, err := json.Marshal(buildMediaStatus(r, 42, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"type":"MEDIA_STATUS"`,
		`"playerState":"PLAYING"`,
		`"playbackRate":1`,
		`"supportedMediaCommands":15`,
		`"streamType":"BUFFERED"`,
		`"metadataType":0`,
		`"duration":52.209`,
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("status JSON missing %s: %s", want, body)
		}
	}
}

func TestClampMediaTime(t *testing.T) {
	media := &MediaInfo{Duration: 10}
	tests := []struct {
		name string
		in   float64
		want float64
	}{
		{name: "negative", in: -1, want: 0},
		{name: "inside", in: 5, want: 5},
		{name: "duration", in: 11, want: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clampMediaTime(tt.in, media); got != tt.want {
				t.Fatalf("clampMediaTime(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSetVolumeClampsLevel(t *testing.T) {
	r := NewReceiver(nil)
	r.SetVolume(Volume{Level: 1.5, Muted: true})

	vol := r.Volume()
	if vol.Level != 1 {
		t.Fatalf("Volume level = %v, want 1", vol.Level)
	}
	if !vol.Muted {
		t.Fatal("Volume muted = false, want true")
	}

	r.Media.mu.Lock()
	defer r.Media.mu.Unlock()
	if r.Media.Volume != vol {
		t.Fatalf("Media volume = %v, want %v", r.Media.Volume, vol)
	}
}

func TestVolumeSharedAcrossLoadAndMediaCommands(t *testing.T) {
	r := NewReceiver(nil)
	s := &Session{receiver: r, conn: &appendConn{}}
	r.SetVolume(Volume{Level: 0.4})
	handleLoad(s, "sender-1", &mediaRequest{Media: &MediaInfo{ContentID: "https://example.test/video"}})
	if got := buildMediaStatus(r, 0, 0).Status[0].Volume; got != r.Volume() {
		t.Fatalf("loaded volume = %v, want %v", got, r.Volume())
	}
	muted := true
	handleMediaVolume(s, "sender-1", &mediaRequest{Volume: &volumePatch{Muted: &muted}})
	if got := r.Volume(); got != (Volume{Level: 0.4, Muted: true}) {
		t.Fatalf("receiver volume after media mute = %v", got)
	}
}
