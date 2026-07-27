# cast-receiver

Minimal Google Cast receiver — advertises on your LAN, accepts Cast v2 connections, plays media. One binary, zero runtime deps.

```
go build . && ./cast-receiver
```

## What it does

- mDNS advertisement as `_googlecast._tcp` — senders discover it automatically
- TLS listener on port 8009 (self-signed cert auto-generated on first run)
- Cast v2 protocol: CONNECT, heartbeat, GET_STATUS, LAUNCH, LOAD, PLAY, PAUSE, STOP
- Local media playback via `ffplay`
- In-memory session state, one sender at a time

## Usage

```sh
./cast-receiver -name "My Cast Device" -port 8009
```

Cast from any Chrome tab or Android device — the receiver appears as a Cast target.

## Build

```sh
go build .
```

Cross-platform builds via GoReleaser:

```sh
goreleaser release --clean --snapshot
```

## Project structure

```
├── main.go             # mDNS + TLS listener + self-signed cert
├── cast/
│   ├── protocol.go     # Cast frame: length-prefixed protobuf
│   ├── server.go       # Session handler + namespace routing
│   └── media.go        # LOAD/PLAY/PAUSE/STOP + ffplay launch
├── castpb/             # Generated CastMessage protobuf
├── .goreleaser.yaml
└── .github/workflows/  # CI + release workflows
```

## License

MIT
