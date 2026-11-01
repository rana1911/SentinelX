// Command sentinelx-server exposes the audit pipeline over HTTP so the web
// UI can submit a repository and watch the audit stream back. It serves the
// built UI (from -web) and two endpoints:
//
//	GET  /api/health         -> {"ok":true, "provider":...}
//	GET  /api/audit?repo=... -> Server-Sent Events: progress, then the report
//
// SECURITY: an audit compiles and runs code from the submitted repo plus
// AI-written exploits. That is untrusted code executed on this host. Run this
// behind a sandbox (container/VM, no secrets, limited network) before exposing
// it publicly. For a local demo it's fine. Set SENTINELX_ALLOW_LOCAL=1 to
// also accept local directory paths (handy for testing without a GitHub repo).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/rana1911/sentinelx/internal/agent"
	"github.com/rana1911/sentinelx/internal/fetchrepo"
	"github.com/rana1911/sentinelx/internal/pipeline"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	webDir := flag.String("web", "web/dist", "directory of the built web UI (optional)")
	solc := flag.String("solc", os.Getenv("SENTINELX_SOLC"), "solc binary for forge --use (optional)")
	maxHyp := flag.Int("max-hypotheses", 6, "cap on hypotheses per audit")
	conc := flag.Int("concurrency", 3, "max hypotheses proven in parallel")
	flag.Parse()

	srv := &server{solc: *solc, maxHyp: *maxHyp, conc: *conc, allowLocal: os.Getenv("SENTINELX_ALLOW_LOCAL") == "1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", srv.health)
	mux.HandleFunc("/api/audit", srv.audit)
	if st, err := os.Stat(*webDir); err == nil && st.IsDir() {
		mux.Handle("/", http.FileServer(http.Dir(*webDir)))
		log.Printf("serving UI from %s", *webDir)
	} else {
		log.Printf("no web UI at %s (API only); build it with: cd web && npm run build", *webDir)
	}

	log.Printf("sentinelx-server listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}

type server struct {
	solc       string
	maxHyp     int
	conc       int
	allowLocal bool
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	provider, model := "", ""
	if c, err := agent.NewFromEnv(); err == nil {
		provider, model = string(c.Provider), c.Model
	}
	writeJSON(w, map[string]any{"ok": true, "provider": provider, "model": model})
}

// audit streams a full audit for ?repo=<github url or local path> as SSE.
func (s *server) audit(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	contract := r.URL.Query().Get("contract")
	if repo == "" {
		http.Error(w, "missing ?repo", http.StatusBadRequest)
		return
	}
	if !fetchrepo.IsGitHubURL(repo) && !s.allowLocal {
		http.Error(w, "only GitHub URLs are accepted", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	send := func(e pipeline.Event) {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	fail := func(msg string) {
		send(pipeline.Event{Stage: "error", Message: msg})
	}

	// Overall timeout so a hung clone/build/model can't wedge the stream.
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Minute)
	defer cancel()

	client, err := agent.NewFromEnv()
	if err != nil {
		fail("model client not configured: " + err.Error())
		return
	}
	send(pipeline.Event{Stage: "note", Message: fmt.Sprintf("model: %s (%s)", client.Model, client.Provider)})

	// Stage 0: fetch + prepare the repo.
	send(pipeline.Event{Stage: "ingest", Message: "fetching repository"})
	prep, err := fetchrepo.Prepare(ctx, repo, s.solc, func(m string) { send(pipeline.Event{Stage: "ingest", Message: m}) })
	if err != nil {
		fail(err.Error())
		return
	}
	defer prep.Cleanup()

	opts := pipeline.Options{
		ProjectDir:    prep.Dir,
		Solc:          s.solc,
		MaxHypotheses: s.maxHyp,
		Concurrency:   s.conc,
		Timeout:       90 * time.Second,
	}

	spec, err := pipeline.Ingest(ctx, opts, contract, send)
	if err != nil {
		fail("ingestion failed: " + err.Error())
		return
	}
	_, jr, err := pipeline.Run(ctx, client, spec, opts, send)
	if err != nil {
		fail(err.Error())
		return
	}
	send(pipeline.Event{Stage: "done", Message: "audit complete", Report: &jr})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
