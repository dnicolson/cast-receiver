# cast-receiver: Prioritized Roadmap

**Product**: cast-receiver — minimal open-source Google Cast receiver (Go)
**Current**: v0 — mDNS + TLS + Cast v2 protocol + ffplay local-file playback
**Repo**: github.com/grave0x/cast-receiver

---

## Priority tiers

### P0 — Must have (blocking adoption)

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| 1 | **Device Auth** | Medium | Chrome/Android Cast dialogs won't list the receiver. Invisible to 99% of users. |
| 2 | **HTTP Media Proxy** | Medium | ffplay local-file-only is a tech demo. Real casting means remote URLs. |

**P0 order**: Device Auth first (unlocks discovery), then HTTP proxy (unlocks utility). Together they turn a demo into something someone can actually use.

### P1 — Should have (unlock engagement)

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| 3 | **Multi-sender session management** | Medium | Real Cast devices handle multiple senders. Current sequential TLS breaks households. |
| 4 | **Web dashboard + JSON API** | Small-Medium | Web UI at `:8080` for status/control. JSON API for Home Assistant / automation. |
| 5 | **Raspberry Pi deploy kit** | Small | `curl | sh` + systemd + Dockerfile. Low effort, high community visibility. |

### P2 — Nice to have (differentiation)

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| 6 | **Cast-to-file / recording mode** | Medium | Save cast media to disk. Podcast archiving, download automation. |
| 7 | **AirPlay compat layer** | Large | RAOP/AirTunes side-by-side with Cast. Big differentiator, big scope. |
| 8 | **Custom Cast app framework (CAF-lite)** | Large | JS receiver apps in `goja`. Third-party devs build on the platform. |

---

## Effort legend

| Effort | Rough estimate |
|--------|---------------|
| Small | 1-2 days |
| Medium | 3-7 days |
| Large | 2-4 weeks |

---

## Dependency graph

```
Device Auth ──────────────────┐
                               ├──► v1.0 (functional Cast receiver)
HTTP Media Proxy ─────────────┘
        │
        ├──► Multi-sender (needs proxy working to test)
        ├──► Web dashboard (needs proxy to show meaningful now-playing)
        └──► Pi deploy kit (wraps whatever exists)

Multi-sender ──► Cast-to-file (needs multi-session tracking)
Web dashboard ──► JSON API (same port, same routes)
```

**Key insight**: Everything depends on Device Auth + HTTP Media Proxy. Until those ship, every other feature is built on sand — nobody can discover the device or cast real content to it.

---

## Recommended phases

### Phase 1: v0.1 — "Works with Chrome" (P0)
- Device Auth so the receiver appears in Chrome Cast dialog
- HTTP Media Proxy so you can cast a YouTube tab
- One-week sprint

### Phase 2: v0.2 — "Household ready" (P1)
- Multi-sender session management
- Web dashboard + JSON API (even if basic)
- One-week sprint

### Phase 3: v0.3 — "Appliance" (P1)
- Dockerfile / systemd service
- Raspberry Pi ARM build in GoReleaser matrix
- `curl https://cast-receiver.sh | sh` install script
- A few days

### Phase 4: v1.0+ — "Platform" (P2)
- Cast-to-file
- AirPlay (if demand materializes)
- Custom app framework (if platform play)
- Ongoing

---

## Build vs buy / reuse decisions

| Feature | Approach |
|---------|----------|
| Device Auth | Reverse-engineer from Chrome Cast source / protocol traces. No library exists. |
| HTTP Proxy | `net/http` stdlib — Go's HTTP handler can byte-range proxy in ~200 lines. |
| Web dashboard | `embed` a single HTML page in the Go binary. Zero JS framework. |
| JSON API | Same HTTP server, different routes. |
| Pi deploy | `Dockerfile` + `goarm` cross-compile. No orchestration needed. |
| AirPlay | `github.com/griff/airplay` or similar — but these are immature. High risk. |
