# uLiquidity/Go

**Liquidity** is a high-performance, production-grade Go library for robust transport-layer traffic obfuscation, anti-censorship, and statistical fingerprinting resistance. It is designed to be embedded into TLS-like transports, providing dense cover traffic, adaptive fragmentation, packet reordering, padding, and advanced flow-morphing features. The project is focused on defeating modern network censorship and traffic analysis while remaining clean, reliable, and easy to integrate.

## Features

- **Advanced Obfuscation Layer:** Fragments, pads, and asynchronously schedules all application data using a custom protocol layered inside TLS records.
- **Dense Cover Traffic:** Supports multiple traffic morphing modes, including dummy fill, burst fill, idle fill, and adaptive EWMA-based fill.
- **Statistical Fingerprint Resistance:** Real and cover traffic are blended to defeat machine learning and DPI.
- **Runtime-Configurable Modes:** All cover strategies are API-switchable without restarting connections.
- **Full Go Standard Library Integration:** Drop-in for existing TLS code; all net.Conn semantics preserved.
- **Production-Grade Robustness:** Strong locking, error handling, resource cleanup, and thorough documentation.

## Quick Start

### 1. Installation

```sh
go get github.com/uLiquidity/Go
```

### 2. Basic Usage

The obfuscation layer is automatically enabled in the modified TLS `Conn`.  
You only need to use `Conn` as you would use Go's standard `tls.Conn`.

Example:

```go
import (
    "github.com/uLiquidity/Go"
    "net"
)

func main() {
    rawConn, err := net.Dial("tcp", "remote.server:443")
    if err != nil {
        panic(err)
    }

    config := &tls.Config{ /* ...your TLS config... */ }
    conn := tls.Client(rawConn, config)

    // Handshake automatically enables obfs
    if err := conn.Handshake(); err != nil {
        panic(err)
    }

    // Use conn as usual
    _, err = conn.Write([]byte("your secret data"))
    // ...
}
```

### 3. Changing Cover Traffic Modes

You can dynamically switch obfuscation strategies at runtime:

```go
// Import obfs constants
import "github.com/uLiquidity/Go/tls"

conn := tls.Client(...)

// Switch to burst fill mode
conn.Obfs().SetCoverMode(tls.ObfsCoverBurst)

// Switch to adaptive EWMA fill mode
conn.Obfs().SetCoverMode(tls.ObfsCoverAdaptiveEWMA)
```

Available modes:

- `ObfsCoverOff` – No dummy/cover traffic
- `ObfsCoverDummy` – Legacy periodic dummy fill
- `ObfsCoverBurst` – Scheduled burst fill
- `ObfsCoverIdleFill` – Idle continuous fill
- `ObfsCoverAdaptiveEWMA` – Adaptive EWMA-based fill

### 4. API Reference

- `func (c *Conn) Obfs() *ObfsConnState`  
  Access the obfuscation state and runtime configuration.
- `func (s *ObfsConnState) SetCoverMode(mode ObfsCoverMode)`  
  Switch cover traffic mode dynamically.

See [obfs.go](obfs.go) for advanced options and internals.

## Protocol Details

- See [`SPEC.md`](SPEC.md) for a full technical specification.
- All protocol fields, fragmentation, scheduling, and cover traffic are described in RFC-style detail.

## Security & Performance Notes

- All randomness and padding use cryptographically secure PRNGs.
- All concurrency is rigorously guarded.
- Errors are never silently ignored; all edge cases are handled.
- For best results, use with a standard TLS stack and avoid using the underlying net.Conn directly.
- Make sure both client and server are using uLiquidity obfs for proper operation—otherwise, fallback to normal TLS.

## Limitations and Compatibility

- Both endpoints MUST support the uLiquidity protocol for proper operation.
- Not compatible with non-uLiquidity peers (unless fallback is negotiated by ALPN or handshake extension).
- Not a replacement for end-to-end encryption—use with TLS 1.3 or later for maximum security.
- For custom protocol negotiation, you may need to extend the handshake.

## Troubleshooting

- If you see `obfs: bad magic` or `obfs: invalid header values`, check that both ends are running compatible versions.
- If the connection appears stalled, ensure cover modes are correctly set and obfs is initialized.
- For best debugging, run with logging enabled and watch for error or panic messages.

## License

see [LICENSE](LICENSE).

## Acknowledgments

Inspired by the research and practice of anti-censorship, pluggable transports, and traffic morphing communities.
