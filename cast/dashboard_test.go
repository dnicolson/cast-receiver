package cast

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardSeek(t *testing.T) {
	for _, tt := range []struct {
		body string
		code int
		want float64
	}{
		{`{"mediaSessionId":1,"currentTime":12}`, http.StatusOK, 12},
		{`{"mediaSessionId":1,"currentTime":90}`, http.StatusOK, 30},
		{`{"mediaSessionId":1,"currentTime":-1}`, http.StatusOK, 0},
		{`{"mediaSessionId":2,"currentTime":12}`, http.StatusConflict, 0},
		{`{"mediaSessionId":1}`, http.StatusBadRequest, 0},
		{`{"currentTime":12}`, http.StatusBadRequest, 0},
		{`invalid`, http.StatusBadRequest, 0},
	} {
		t.Run(tt.body, func(t *testing.T) {
			r := NewReceiver(nil)
			s := &Session{receiver: r, conn: &appendConn{}}
			handleLoad(s, "sender-1", &mediaRequest{Media: &MediaInfo{ContentID: "https://example.test/video", Duration: 30}})
			rr := httptest.NewRecorder()
			controlHandler(r, "SEEK")(rr, httptest.NewRequest(http.MethodPost, "/api/seek", strings.NewReader(tt.body)))
			if rr.Code != tt.code {
				t.Fatalf("status = %d, want %d", rr.Code, tt.code)
			}
			if got := buildMediaStatus(r, 0, 0).Status[0].CurrentTime; got != tt.want {
				t.Fatalf("Cast currentTime = %v, want %v", got, tt.want)
			}
			if (r.Media.seekRevision > 0) != (tt.code == http.StatusOK) {
				t.Fatalf("unexpected seek revision %d", r.Media.seekRevision)
			}
		})
	}
}

func TestCastSeekRevisionIncludesRepeatedTargets(t *testing.T) {
	r := NewReceiver(nil)
	s := &Session{receiver: r, conn: &appendConn{}}
	handleLoad(s, "sender-1", &mediaRequest{Media: &MediaInfo{ContentID: "https://example.test/video"}})
	target := 12.0
	for want := uint64(1); want <= 2; want++ {
		handleSeek(s, "sender-1", &mediaRequest{CurrentTime: &target})
		if r.Media.seekRevision != want || r.Media.CurrentTime != target {
			t.Fatalf("seek revision/time = %d/%v, want %d/%v", r.Media.seekRevision, r.Media.CurrentTime, want, target)
		}
	}
}
