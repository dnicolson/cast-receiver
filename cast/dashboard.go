// Dashboard and JSON API for cast-receiver.
// ponytail: single embedded HTML page, no JS framework, no CSS framework.

package cast

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
)

//go:embed dashboard.html
var dashboardFS embed.FS

// StartDashboard starts the web dashboard + JSON API server on the given port.
func StartDashboard(receiver *Receiver, port int) (func(), error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		receiver.Media.mu.Lock()
		ps := receiver.Media.PlayerState
		ir := receiver.Media.IdleReason
		var cid, ctype, title string
		if receiver.Media.Media != nil {
			cid = receiver.Media.Media.ContentID
			ctype = receiver.Media.Media.ContentType
			if receiver.Media.Media.Metadata != nil {
				title = receiver.Media.Media.Metadata.Title
			}
		}
		receiver.Media.mu.Unlock()

		vol := receiver.Volume()

		receiver.mu.Lock()
		sessionCount := len(receiver.sessions)
		receiver.mu.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"playerState": ps,
			"contentId":   cid,
			"contentType": ctype,
			"title":       title,
			"volume":      vol.Level,
			"muted":       vol.Muted,
			"sessions":    sessionCount,
			"idleReason":  ir,
		})
	})

	mux.HandleFunc("/api/play", controlHandler(receiver, "PLAY"))
	mux.HandleFunc("/api/pause", controlHandler(receiver, "PAUSE"))
	mux.HandleFunc("/api/stop", controlHandler(receiver, "STOP"))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		tmpl, err := template.ParseFS(dashboardFS, "dashboard.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, map[string]interface{}{"Title": "Cast Receiver"})
	})

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("dashboard listen: %w", err)
	}

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)

	log.Printf("dashboard: http://localhost:%d", port)
	return func() { srv.Close(); ln.Close() }, nil
}

func controlHandler(receiver *Receiver, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		receiver.Media.mu.Lock()
		switch action {
		case "PLAY":
			receiver.Media.PlayerState = "PLAYING"
		case "PAUSE":
			receiver.Media.PlayerState = "PAUSED"
		case "STOP":
			receiver.Media.PlayerState = "IDLE"
			receiver.Media.IdleReason = "CANCELLED"
		}
		receiver.Media.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}
