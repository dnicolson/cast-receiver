# cast-receiver

## Project Overview

This project directory is **empty** — no source code, configuration files, or version control exist yet. The name `cast-receiver` suggests the intent to build a Google Cast / Chromecast receiver application (a device or service that implements the Cast receiver protocol, capable of receiving and handling media streams or app sessions from Cast senders).

### Likely Scope (inferred from project name)

A Cast receiver typically listens for Cast protocol traffic on a local network, advertises itself as a Cast-compatible device, and handles media playback or custom Cast application sessions initiated by Cast senders (Chromecast, Google Home, or SDK-integrated apps). Implementations often involve:

- **mDNS/DNS-SD** — advertising the receiver on the local network (e.g. using `_googlecast._tcp` service type)
- **Cast v2 protocol** — the DIAL-based discovery and control protocol over HTTP/TLS
- **Media playback** — receiving and rendering audio/video streams (the `media` namespace)
- **Custom application support** — handling Cast application lifecycle (`app`, `receiver`, `connection` namespaces)

### Known Cast Receiver Implementations

Popular open-source Cast receiver projects include:
- **unifiedremote/** — various attempts at Cast receiver implementations
- **alex9849/mediacast-server** — Cast-compatible streaming server
- **ouroboros/** — custom Cast receiver implementations in various languages
- **Node.js** — `castv2-client` ecosystem (sender-side, but the protocol is understood)
- **Go / Rust** — embedded receiver implementations for media devices

## Build and Test Commands

No build or test commands exist yet. This section should be updated once a build system is chosen.

Likely candidates:
- **Go**: `go build ./...`, `go test ./...`
- **Node/TypeScript**: `npm run build`, `npm test`, `npm run dev`
- **Python**: `poetry build`, `pytest`
- **Rust**: `cargo build`, `cargo test`, `cargo clippy`
- **C/C++**: `cmake --build build`, `ctest`

## Technology Stack

Undefined. The technology stack should be chosen based on:

| Consideration | Options |
|---|---|
| **Runtime** | Go (good networking/stdlib), Node.js (fast prototyping), Rust (performance/safety), Python (prototyping), C/C++ (embedded) |
| **mDNS** | DNS-SD via Avahi (Linux), Bonjour (macOS), or pure-Go `hashicorp/mdns` |
| **TLS** | Cast v2 requires TLS encryption; self-signed certs are typical for development |
| **Protocol** | Google Cast v2 protocol over HTTP/2 or WebSocket |
| **Media** | FFmpeg/libav for transcoding, or direct streaming via HTTP range requests |

## Code Style Guidelines

To be defined once a language is chosen.

### General Principles (once code exists):

- Prefer the standard library's networking primitives where possible
- Follow protocol specifications strictly (Cast protocol is reverse-engineered and version-sensitive)
- Keep the receiver module self-contained for easy reuse
- Use structured logging (zerolog for Go, `log` crate for Rust, `winston` for Node)
- Handle network errors gracefully — Cast receivers must survive network interruptions

## Testing Instructions

No tests exist yet. When tests are added:

### Test Strategy

- **Unit tests**: Protocol message parsing/serialization
- **Integration tests**: mDNS advertisement + TLS handshake
- **End-to-end**: Real Cast sender device/emulator connecting to receiver
- **Fuzzing**: Cast protocol message field fuzzing on the receiver port

### Dependencies for Testing

- A real or emulated Chromecast/Google Home sender (phone, Chrome browser with Cast extension, or `castv2-client`)
- Wireshark or tcpdump for protocol debugging
- `mDNS` browsing tools: `avahi-browse` (Linux), `dns-sd` (macOS)

## Security Considerations

- **TLS certificates**: Cast v2 uses client-authenticated TLS. Self-signed certificates are acceptable for testing but consider proper PKI for production.
- **Local network exposure**: Cast receivers are local-network services. Do not expose the Cast receiver port to the public internet.
- **Input validation**: The Cast protocol accepts arbitrary application messages — validate all incoming data before processing.
- **Media access**: Restrict which media sources the receiver can stream from to prevent SSRF.
- **Authentication**: The Cast protocol itself has minimal authentication; rely on network segmentation for security.
- **Secrets**: No API keys, certificates, or credentials should be committed to version control.

## Discovery and Protocol Reference

- [Google Cast v2 Protocol (unofficial docs)](https://github.com/thibauts/node-castv2)
- [DIAL protocol specification](http://www.dial-multiscreen.org/specification)
- [mDNS / DNS-SD (RFC 6762, RFC 6763)](https://datatracker.ietf.org/doc/html/rfc6762)

## Future Setup Checklist

Once the project scaffold is created:

1. Initialize version control (`git init`)
2. Choose language and set up build system
3. Add `.gitignore` (exclude `target/`, `node_modules/`, `.env`, `*.local.*`, OS junk files)
4. Implement mDNS advertisement first (simplest standalone piece)
5. Implement Cast TLS listener
6. Implement base Cast protocol message loop
7. Implement media streaming capability

---

*This `AGENTS.md` was generated for an empty project directory. Update it as the project evolves.*
