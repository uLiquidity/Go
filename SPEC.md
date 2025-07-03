# Liquidity Protocol Specification

## 1. Introduction

The Liquidity Protocol is an application-layer obfuscation and anti-censorship protocol designed to encapsulate arbitrary data streams over a transport that emulates standard TLS records. Its primary goals are:

- To resist traffic analysis and censorship by fragmenting, delaying, padding, and reordering payloads in a manner indistinguishable from legitimate TLS streams.
- To provide cover traffic, including dummy data, burst fill, idle fill, and adaptive padding, such that the real traffic ratio is minimized.
- To maintain compatibility with the external characteristics of TLS, enabling seamless operation in environments with deep packet inspection (DPI).

## 2. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 [[RFC2119]](https://datatracker.ietf.org/doc/html/rfc2119).

## 3. Protocol Overview

Liquidity operates as a framing and obfuscation layer within the TLS record plaintext, prior to cryptographic processing. All obfuscation, fragmentation, and padding actions MUST occur before TLS encryption and after TLS decryption. The protocol is designed such that all observable features on the network are indistinguishable from vanilla TLS records.

Liquidity introduces its own message framing, header, and fragmentation logic, implemented entirely in the plaintext region of each TLS Application Data record.

## 4. Packet Format

Each Liquidity protocol packet (a "fragment") is structured as follows:

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Magic(2)    |Ver|Flg|        Seq (4)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Timestamp (8)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        RandID (4)              |  PayloadLen (2) | TotalLen(2)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload (variable)                        |
+-------------------------------+-------------------------------+
|                     Padding (variable)                        |
+-------------------------------+-------------------------------+
```

### Field Definitions

- **Magic (2 bytes, uint16, Big Endian):**  
  Fixed value `0x4D58` to identify a Liquidity packet.
- **Version (1 byte, uint8):**  
  Protocol version. Current: `0x03`.
- **Flags (1 byte, uint8):**  
  Bitmask for control information (e.g., dummy packet: `0x01`).
- **Seq (4 bytes, uint32, Big Endian):**  
  Monotonically increasing sequence number for in-order delivery. Dummy packets use `0xFFFFFFFF`.
- **Timestamp (8 bytes, int64, Big Endian):**  
  Milliseconds since Unix epoch, indicating when the packet was scheduled for send.
- **RandID (4 bytes, uint32, Big Endian):**  
  Random identifier for correlation, replay resistance, and additional entropy.
- **PayloadLen (2 bytes, uint16, Big Endian):**  
  Length of the actual application payload.
- **TotalLen (2 bytes, uint16, Big Endian):**  
  Length of the entire packet, including header, payload, and padding.
- **Payload:**  
  Application data, up to `ObfsMaxFrag` bytes per fragment.
- **Padding:**  
  Random bytes to reach the specified fragment size. Padding length = `TotalLen - HeaderLen - PayloadLen`.

## 5. Fragmentation and Reassembly

- **Fragmentation:**  
  Application data MUST be split into fragments of random length between `ObfsMinFrag` and `ObfsMaxFrag` bytes (including payload and padding). Each fragment is independently constructed and scheduled.
- **Padding:**  
  Each fragment is padded with cryptographically random bytes to reach its specified length.
- **Reassembly:**  
  The receiver MUST buffer fragments and deliver payloads in strict sequence order, using the `Seq` field. Out-of-order fragments within a window (`ObfsMaxSkew`) MAY be temporarily buffered.

## 6. Cover Traffic and Modes

Liquidity supports multiple cover traffic strategies to defeat statistical and timing analysis:

- **Dummy Packets:**  
  Fragments with the dummy flag set and zero payload, sent at random or scheduled intervals.
- **Burst Fill:**  
  Periodically, a burst of dummy packets is sent to simulate realistic traffic surges.
- **Idle Fill:**  
  During idle periods, dummy packets are injected at configurable intervals to mask inactivity.
- **Adaptive EWMA Fill:**  
  An Exponential Weighted Moving Average (EWMA) of real traffic is maintained. If real traffic falls below a target threshold, adaptive dummy packets are injected to maintain a constant traffic profile.
- **Mode Switching:**  
  The cover traffic mode can be changed at runtime via an API (see Section 12).

## 7. Transmission Scheduling

- Each fragment, real or cover, is assigned a randomized send time within a maximum delay window (`ObfsMaxDelay`).
- A priority queue is maintained to ensure correct scheduling.
- Packet write and scheduling logic MUST be thread-safe and handle concurrent access.

## 8. Error Handling

- All protocol errors (e.g., bad magic, header corruption, impossible lengths, buffer overflows) MUST be detected and handled gracefully.
- Duplicate, out-of-window, or old fragments MUST be dropped without impacting subsequent reassembly.
- All errors MUST be logged and, where applicable, surfaced to the application layer.

## 9. Security Considerations

- All randomness MUST be generated using a cryptographically secure PRNG.
- Padding MUST not leak application data lengths.
- Sequence numbers and timestamps MUST be constructed such that replay and reordering attacks are mitigated.
- The protocol is designed to resist both passive and active network analysis.

## 10. Negotiation and Compatibility

- Both endpoints MUST agree to use the Liquidity protocol, including the version and cover traffic mode.
- The protocol is only active if enabled on both sides; otherwise, fallback to standard TLS is recommended.
- Backward compatibility and negotiation logic are out of scope for this document, but may be implemented via ALPN or custom handshake extensions.

## 11. Parameter Summary

| Parameter     | Value (default) | Description                                 |
|:--------------|:---------------:|:--------------------------------------------|
| Magic         | 0x4D58          | Protocol magic number                       |
| Version       | 0x03            | Protocol version                            |
| HeaderLen     | 24 bytes        | Header length                               |
| MinFrag       | 800 bytes       | Minimum fragment (payload+padding) size     |
| MaxFrag       | 1200 bytes      | Maximum fragment (payload+padding) size     |
| MaxDelay      | 350ms           | Maximum send scheduling delay               |
| MaxSkew       | 8               | Max out-of-order receive window             |
| DummyRatio    | 0.25            | Probability for dummy packet insertion      |
| DummyInterval | 180ms           | Min interval between dummy packets          |
| BurstInterval | 2s              | Burst fill interval                         |
| BurstCount    | 15              | Packets per burst fill                      |
| IdleFillIntvl | 70ms            | Idle period dummy packet interval           |
| EWMAAlpha     | 0.2             | Smoothing factor for EWMA adaptive fill     |

## 12. API and Runtime Control

- The implementation MUST provide an API to set the cover traffic mode at runtime.
- Supported modes include:
    - `ObfsCoverOff` (no dummy)
    - `ObfsCoverDummy` (legacy periodic dummy)
    - `ObfsCoverBurst` (scheduled burst fill)
    - `ObfsCoverIdleFill` (idle continuous fill)
    - `ObfsCoverAdaptiveEWMA` (adaptive EWMA-based fill)
- The API MUST be thread-safe and changes take effect immediately.

## 13. IANA Considerations

This protocol does not require any IANA actions.

## 14. References

- [RFC2119] S. Bradner, "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [TLS 1.3] RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3.

---

**Author:** uLiquidity Project  
**Status:** STANDARD  
**Intended status:** Experimental  
