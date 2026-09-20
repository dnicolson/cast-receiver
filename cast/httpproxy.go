package cast

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
)

// ProxyServer is a one-shot HTTP reverse proxy for a single remote URL.
// ponytail: single-URL, no connection pooling, no TLS upgrade for backend. Add if we proxy HTTPS->HTTPS regularly.
type ProxyServer struct {
	ln     net.Listener
	server *http.Server
	mu     sync.Mutex
	remote string
}

// StartProxy starts a local HTTP server on a random port that proxies to remoteURL.
// Returns the local port and a stop function.
func StartProxy(remoteURL string) (int, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Printf("proxy: listen error: %v", err)
		return 0, nil
	}

	p := &ProxyServer{
		ln:     ln,
		remote: remoteURL,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", p.handleStream)
	mux.HandleFunc("/", p.handleStream)

	p.server = &http.Server{Handler: mux}
	go p.server.Serve(ln)

	port := ln.Addr().(*net.TCPAddr).Port
	log.Printf("proxy: started for %s on 127.0.0.1:%d", remoteURL, port)

	return port, func() {
		p.server.Close()
		ln.Close()
	}
}

func (p *ProxyServer) handleStream(w http.ResponseWriter, r *http.Request) {
	ProxyMedia(w, r, p.remote)
}

// ProxyMedia proxies an HTTP media URL to the dashboard's same-origin player.
func ProxyMedia(w http.ResponseWriter, r *http.Request, source string) {
	if source == "" {
		http.Error(w, "no media loaded", http.StatusNotFound)
		return
	}
	if r.Method == http.MethodOptions {
		writeProxyCORS(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build proxied request
	upstream := normalizeHTTPMediaURL(source)
	u, err := url.Parse(upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "unsupported media URL scheme", http.StatusBadRequest)
		return
	}
	req, err := http.NewRequest(r.Method, upstream, nil)
	if err != nil {
		http.Error(w, "bad request", http.StatusInternalServerError)
		return
	}

	// Copy Range header for seeking support
	// ponytail: only Range is forwarded; add more headers (Accept, etc.) if senders require them
	if rng := r.Header.Get("Range"); rng != "" {
		req.Header.Set("Range", rng)
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Printf("proxy: fetch error: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers (selectively — add CORS)
	writeProxyCORS(w)

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		w.Header().Set("Content-Range", cr)
	}
	if ar := resp.Header.Get("Accept-Ranges"); ar != "" {
		w.Header().Set("Accept-Ranges", ar)
	}
	// ponytail: only a minimal set of headers forwarded; full passthrough if senders fail

	w.WriteHeader(resp.StatusCode)
	written, _ := io.Copy(w, resp.Body)
	log.Printf("proxy: %s %s -> %d (%d bytes)", r.Method, source, resp.StatusCode, written)
}

func writeProxyCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Range, Content-Type")
}

// GetPage is a helper to fetch a URL and return the body as string.
// Used internally when resolving media URLs. (ponytail: unused for now, placeholder)
func GetPage(url string) (string, error) {
	resp, err := http.Get(normalizeHTTPMediaURL(url))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
