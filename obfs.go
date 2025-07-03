// Copyright 2025 The uLiquidity Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// obfs.go implements the ObfsConnState, a transport-layer
// asynchronous packet fragmentation, delay, and reordering
// mechanism for TLS anti-censorship. This module is designed
// for high robustness, concurrency, and code clarity, matching
// Go standard library quality and style.

package tls

import (
	"bytes"
	"container/heap"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	mathrand "math/rand"
	"sync"
	"time"
)

// Protocol constants and tunables.
// Obfs protocol version.
const (
	ObfsMagic         = 0x4D58      // Protocol magic (2 bytes)
	ObfsVersion       = 0x03        // Protocol version (1 byte)
	ObfsHeaderLen     = 24          // Header length in bytes
	ObfsMinFrag       = 800         // Minimum payload+padding per fragment
	ObfsMaxFrag       = 1200        // Maximum payload+padding per fragment
	ObfsMaxDelay      = 350 * time.Millisecond // Maximum random send delay per packet
	ObfsMaxSkew       = 8           // Maximum out-of-order receive window
	ObfsDummyRatio    = 0.25        // Probability of dummy packet insertion
	ObfsDummyInterval = 180 * time.Millisecond // Minimum interval between dummy packets
)

// ObfsFlagDummy indicates a dummy (cover) packet.
const (
	ObfsFlagDummy = 0x01
)

// obfsHeader describes the per-fragment protocol header.
// All fields are in big-endian network order.
type obfsHeader struct {
	Magic      uint16 // Constant protocol magic
	Version    uint8  // Protocol version
	Flags      uint8  // Flags (e.g., dummy)
	Seq        uint32 // Packet sequence number
	Timestamp  int64  // Unix msec, send time
	RandID     uint32 // Random identifier
	PayloadLen uint16 // Actual application payload length
	TotalLen   uint16 // Total length (header+payload+padding)
}

// obfsPacket represents a queued fragment for transmission.
type obfsPacket struct {
	hdr    obfsHeader
	data   []byte
	sentAt time.Time // Scheduled send time
}

// obfsPacketHeap implements heap.Interface for obfsPacket.
type obfsPacketHeap []obfsPacket

func (h obfsPacketHeap) Len() int           { return len(h) }
func (h obfsPacketHeap) Less(i, j int) bool { return h[i].sentAt.Before(h[j].sentAt) }
func (h obfsPacketHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *obfsPacketHeap) Push(x interface{}) { *h = append(*h, x.(obfsPacket)) }
func (h *obfsPacketHeap) Pop() interface{} {
	old := *h
	n := len(old)
	ret := old[n-1]
	*h = old[:n-1]
	return ret
}

// ObfsConnState manages asynchronous, robust obfs-layer
// fragmentation, queueing, reordering, and dummy packets.
//
// All methods are safe for concurrent use after creation.
type ObfsConnState struct {
	// Write (send) side
	seqWrite    uint32            // Next sequence number to use
	writeQueue  obfsPacketHeap    // Heap-ordered by sentAt
	writeMu     sync.Mutex        // Guards writeQueue and writeClosed
	writeCond   *sync.Cond        // Signals asyncSender
	netWriter   func([]byte) error // Lower-layer send function
	stopCh      chan struct{}     // Signals send goroutines to stop
	writeClosed bool              // Set when shutdown

	// Read (receive) side
	seqRead     uint32            // Next expected sequence number
	readBuf     bytes.Buffer      // Buffered incoming obfs data
	readReorder map[uint32][]byte // Out-of-order receive buffer
	readMu      sync.Mutex        // Guards readBuf, readReorder, readClosed
	readClosed  bool              // Set when shutdown
}

// NewObfsConnState creates and launches an ObfsConnState.
// netWriter is called synchronously from the sender goroutine.
func NewObfsConnState(netWriter func([]byte) error) *ObfsConnState {
	state := &ObfsConnState{
		netWriter:   netWriter,
		stopCh:      make(chan struct{}),
		readReorder: make(map[uint32][]byte),
	}
	state.writeCond = sync.NewCond(&state.writeMu)
	go state.asyncSender()
	go state.periodicDummySender()
	return state
}

// WriteObfs splits, pads, and schedules the given application data for
// obfs transmission. The function is safe for concurrent use.
// Returns the number of input bytes accepted or an error.
func (s *ObfsConnState) WriteObfs(b []byte) (int, error) {
	if b == nil {
		return 0, io.ErrUnexpectedEOF
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed {
		return 0, io.ErrClosedPipe
	}
	total := len(b)
	sent := 0
	for sent < total {
		fragLen := ObfsMinFrag + mathrand.Intn(ObfsMaxFrag-ObfsMinFrag+1)
		left := total - sent
		payloadLen := fragLen
		if left < fragLen {
			payloadLen = left
		}
		paddingLen := fragLen - payloadLen

		now := time.Now().UnixNano() / 1e6
		randID := mathrand.Uint32()
		h := obfsHeader{
			Magic:      ObfsMagic,
			Version:    ObfsVersion,
			Flags:      0,
			Seq:        s.seqWrite,
			Timestamp:  now,
			RandID:     randID,
			PayloadLen: uint16(payloadLen),
			TotalLen:   uint16(ObfsHeaderLen + fragLen),
		}
		s.seqWrite++

		buf := make([]byte, ObfsHeaderLen)
		binary.BigEndian.PutUint16(buf[0:2], h.Magic)
		buf[2] = h.Version
		buf[3] = h.Flags
		binary.BigEndian.PutUint32(buf[4:8], h.Seq)
		binary.BigEndian.PutUint64(buf[8:16], uint64(h.Timestamp))
		binary.BigEndian.PutUint32(buf[16:20], h.RandID)
		binary.BigEndian.PutUint16(buf[20:22], h.PayloadLen)
		binary.BigEndian.PutUint16(buf[22:24], h.TotalLen)

		buf = append(buf, b[sent:sent+payloadLen]...)
		sent += payloadLen

		if paddingLen > 0 {
			pad := make([]byte, paddingLen)
			if _, err := rand.Read(pad); err != nil {
				return sent, err
			}
			buf = append(buf, pad...)
		}

		// Schedule for async send with randomized delay.
		delay := time.Duration(math.Abs(mathrand.NormFloat64() * float64(ObfsMaxDelay/6)))
		if delay > ObfsMaxDelay {
			delay = ObfsMaxDelay
		}
		schAt := time.Now().Add(delay)
		pkt := obfsPacket{hdr: h, data: buf, sentAt: schAt}
		heap.Push(&s.writeQueue, pkt)
		s.writeCond.Signal()
	}
	return total, nil
}

// CloseWrite signals the sender goroutine to drain and exit.
func (s *ObfsConnState) CloseWrite() {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed {
		return
	}
	s.writeClosed = true
	close(s.stopCh)
	s.writeCond.Signal()
}

// asyncSender is the goroutine responsible for packet
// reordering, randomized delay, and sending to netWriter.
func (s *ObfsConnState) asyncSender() {
	for {
		s.writeMu.Lock()
		for s.writeQueue.Len() == 0 && !s.writeClosed {
			s.writeCond.Wait()
		}
		if s.writeClosed && s.writeQueue.Len() == 0 {
			s.writeMu.Unlock()
			return
		}
		// Pop the earliest scheduled packet.
		pkt := heap.Pop(&s.writeQueue).(obfsPacket)
		now := time.Now()
		wait := pkt.sentAt.Sub(now)
		s.writeMu.Unlock()
		// Wait until scheduled send time.
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-s.stopCh:
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		// Write to lower-layer. Errors are non-fatal.
		_ = s.netWriter(pkt.data)
	}
}

// periodicDummySender regularly injects dummy packets to mask
// silence and make traffic patterns less predictable.
func (s *ObfsConnState) periodicDummySender() {
	ticker := time.NewTicker(ObfsDummyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			if mathrand.Float64() < ObfsDummyRatio {
				s.sendDummyPacket()
			}
		}
	}
}

// sendDummyPacket enqueues a dummy packet for immediate send.
func (s *ObfsConnState) sendDummyPacket() {
	padlen := ObfsMinFrag + mathrand.Intn(ObfsMaxFrag-ObfsMinFrag+1)
	h := obfsHeader{
		Magic:      ObfsMagic,
		Version:    ObfsVersion,
		Flags:      ObfsFlagDummy,
		Seq:        math.MaxUint32,
		Timestamp:  time.Now().UnixNano() / 1e6,
		RandID:     mathrand.Uint32(),
		PayloadLen: 0,
		TotalLen:   uint16(ObfsHeaderLen + padlen),
	}
	buf := make([]byte, ObfsHeaderLen+padlen)
	binary.BigEndian.PutUint16(buf[0:2], h.Magic)
	buf[2] = h.Version
	buf[3] = h.Flags
	binary.BigEndian.PutUint32(buf[4:8], h.Seq)
	binary.BigEndian.PutUint64(buf[8:16], uint64(h.Timestamp))
	binary.BigEndian.PutUint32(buf[16:20], h.RandID)
	binary.BigEndian.PutUint16(buf[20:22], h.PayloadLen)
	binary.BigEndian.PutUint16(buf[22:24], h.TotalLen)
	if _, err := rand.Read(buf[ObfsHeaderLen:]); err != nil {
		// Fail silently, dummy packet dropped.
		return
	}
	s.writeMu.Lock()
	if !s.writeClosed {
		pkt := obfsPacket{hdr: h, data: buf, sentAt: time.Now()}
		heap.Push(&s.writeQueue, pkt)
		s.writeCond.Signal()
	}
	s.writeMu.Unlock()
}

// FeedInput buffers new obfs-protocol plaintext data into the state.
// It is safe for concurrent use.
func (s *ObfsConnState) FeedInput(data []byte) {
	if len(data) == 0 {
		return
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	_, _ = s.readBuf.Write(data)
}

// ReadObfs attempts to extract a single, in-order application
// data fragment from the buffer, returning the number of bytes
// written to b. If no complete data is available, returns (0, nil).
// Returns an error on protocol violation or buffer corruption.
func (s *ObfsConnState) ReadObfs(b []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
		// Check for complete obfs header.
		if s.readBuf.Len() < ObfsHeaderLen {
			return 0, nil
		}
		head := s.readBuf.Bytes()[:ObfsHeaderLen]
		if binary.BigEndian.Uint16(head[0:2]) != ObfsMagic {
			return 0, errors.New("obfs: bad magic")
		}
		flags := head[3]
		seq := binary.BigEndian.Uint32(head[4:8])
		payloadLen := int(binary.BigEndian.Uint16(head[20:22]))
		totalLen := int(binary.BigEndian.Uint16(head[22:24]))

		if totalLen < ObfsHeaderLen || payloadLen < 0 || payloadLen > totalLen-ObfsHeaderLen {
			return 0, errors.New("obfs: invalid header values")
		}
		if s.readBuf.Len() < totalLen {
			return 0, nil // Not enough data for full packet
		}
		// Consume header
		_, _ = s.readBuf.Read(make([]byte, ObfsHeaderLen))
		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(&s.readBuf, payload); err != nil {
				return 0, err
			}
		}
		// Skip padding
		paddingToSkip := totalLen - ObfsHeaderLen - payloadLen
		if paddingToSkip > 0 {
			_, _ = s.readBuf.Read(make([]byte, paddingToSkip))
		}

		// Dummy packets are ignored
		if flags&ObfsFlagDummy != 0 {
			continue
		}
		// In-order delivery
		if seq == s.seqRead {
			n := copy(b, payload)
			s.seqRead++
			return n, nil
		}
		// Out-of-order, but within allowed window: buffer
		if seq > s.seqRead && seq-s.seqRead < ObfsMaxSkew {
			s.readReorder[seq] = payload
			// Immediately check if we can now deliver next in-order
			for {
				p, ok := s.readReorder[s.seqRead]
				if !ok {
					break
				}
				n := copy(b, p)
				delete(s.readReorder, s.seqRead)
				s.seqRead++
				return n, nil
			}
			continue
		}
		// Old/duplicate/out-of-window: drop and continue.
	}
}

// CloseRead marks the receive-side as closed.
func (s *ObfsConnState) CloseRead() {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.readClosed = true
}
