// Copyright 2025 The uLiquidity Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// obfs.go implements the ObfsConnState, a transport-layer
// asynchronous packet fragmentation, delay, and reordering
// mechanism for TLS anti-censorship. This version includes
// dense cover traffic with burst mode, idle fill, scheduled
// bursts, and EWMA-based adaptive fill. Modes are runtime
// switchable via API.

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
const (
	ObfsMagic         = 0x4D58
	ObfsVersion       = 0x03
	ObfsHeaderLen     = 24
	ObfsMinFrag       = 800
	ObfsMaxFrag       = 1200
	ObfsMaxDelay      = 350 * time.Millisecond
	ObfsMaxSkew       = 8
	ObfsDefaultDummyRatio    = 0.25
	ObfsDefaultDummyInterval = 180 * time.Millisecond
	ObfsBurstFillInterval    = 2 * time.Second
	ObfsBurstFillCount       = 15
	ObfsIdleFillInterval     = 70 * time.Millisecond
	ObfsEWMAAlpha            = 0.2 // EWMA smoothing factor
)

// Obfs cover traffic modes.
type ObfsCoverMode int

const (
	ObfsCoverOff ObfsCoverMode = iota // no cover traffic
	ObfsCoverDummy                    // periodic dummy (default, legacy)
	ObfsCoverBurst                    // burst fill mode
	ObfsCoverIdleFill                 // idle fill mode
	ObfsCoverAdaptiveEWMA             // EWMA adaptive cover
)

const (
	ObfsFlagDummy = 0x01
)

// obfsHeader describes the per-fragment protocol header.
type obfsHeader struct {
	Magic      uint16
	Version    uint8
	Flags      uint8
	Seq        uint32
	Timestamp  int64
	RandID     uint32
	PayloadLen uint16
	TotalLen   uint16
}

// obfsPacket represents a queued fragment for transmission.
type obfsPacket struct {
	hdr    obfsHeader
	data   []byte
	sentAt time.Time
}

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

// EWMA tracks Exponential Weighted Moving Average.
type EWMA struct {
	avg   float64
	alpha float64
	init  bool
}

func (e *EWMA) Update(val float64) {
	if !e.init {
		e.avg = val
		e.init = true
		return
	}
	e.avg = e.alpha*val + (1-e.alpha)*e.avg
}

func (e *EWMA) Value() float64 {
	return e.avg
}

// ObfsConnState manages asynchronous, robust obfs-layer
// fragmentation, queueing, reordering, and dummy packets.
// Now supports dense cover traffic and multiple fill modes.
type ObfsConnState struct {
	// Write (send) side
	seqWrite    uint32
	writeQueue  obfsPacketHeap
	writeMu     sync.Mutex
	writeCond   *sync.Cond
	netWriter   func([]byte) error
	stopCh      chan struct{}
	writeClosed bool

	// Read (receive) side
	seqRead     uint32
	readBuf     bytes.Buffer
	readReorder map[uint32][]byte
	readMu      sync.Mutex
	readClosed  bool

	// Cover traffic/idle fill
	coverMode     ObfsCoverMode
	coverMu       sync.RWMutex
	lastSent      time.Time
	appBytesEWMA  EWMA
	coverTimer    *time.Timer
	coverStop     chan struct{}
	adaptiveEWMA  EWMA
}

// NewObfsConnState creates and launches an ObfsConnState.
// You may call SetCoverMode at any time to change fill strategy.
func NewObfsConnState(netWriter func([]byte) error) *ObfsConnState {
	state := &ObfsConnState{
		netWriter:   netWriter,
		stopCh:      make(chan struct{}),
		readReorder: make(map[uint32][]byte),
		coverMode:   ObfsCoverDummy,
		coverStop:   make(chan struct{}),
	}
	state.writeCond = sync.NewCond(&state.writeMu)
	go state.asyncSender()
	go state.coverTrafficManager()
	return state
}

// SetCoverMode sets the dense cover traffic mode at runtime.
// See ObfsCoverMode for modes.
func (s *ObfsConnState) SetCoverMode(mode ObfsCoverMode) {
	s.coverMu.Lock()
	defer s.coverMu.Unlock()
	// Signal any previous cover goroutines to exit.
	select {
	case <-s.coverStop:
	default:
		close(s.coverStop)
	}
	// Start new cover manager if needed.
	s.coverMode = mode
	s.coverStop = make(chan struct{})
	go s.coverTrafficManager()
}

// WriteObfs splits, pads, and schedules the given application data for transmission.
// Updates EWMA bandwidth for adaptive fill.
func (s *ObfsConnState) WriteObfs(b []byte) (int, error) {
	if b == nil {
		return 0, io.ErrUnexpectedEOF
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed {
		return 0, io.ErrClosedPipe
	}
	now := time.Now()
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

		ts := now.UnixNano() / 1e6
		randID := mathrand.Uint32()
		h := obfsHeader{
			Magic:      ObfsMagic,
			Version:    ObfsVersion,
			Flags:      0,
			Seq:        s.seqWrite,
			Timestamp:  ts,
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
		delay := time.Duration(math.Abs(mathrand.NormFloat64() * float64(ObfsMaxDelay/6)))
		if delay > ObfsMaxDelay {
			delay = ObfsMaxDelay
		}
		schAt := time.Now().Add(delay)
		pkt := obfsPacket{hdr: h, data: buf, sentAt: schAt}
		heap.Push(&s.writeQueue, pkt)
		s.writeCond.Signal()
	}
	// Update EWMA for adaptive fill
	s.coverMu.Lock()
	s.lastSent = now
	s.appBytesEWMA.Update(float64(total))
	s.coverMu.Unlock()
	return total, nil
}

// asyncSender: packet reordering, randomized delay, and sending.
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
		pkt := heap.Pop(&s.writeQueue).(obfsPacket)
		now := time.Now()
		wait := pkt.sentAt.Sub(now)
		s.writeMu.Unlock()
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-s.stopCh:
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		_ = s.netWriter(pkt.data)
	}
}

func (s *ObfsConnState) makeDummyPacket() []byte {
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
		return nil
	}
	return buf
}

// coverTrafficManager manages cover/dummy traffic generation according to chosen mode.
func (s *ObfsConnState) coverTrafficManager() {
	mode := s.coverMode
	switch mode {
	case ObfsCoverOff:
		return
	case ObfsCoverDummy:
		s.coverDummyLegacy()
	case ObfsCoverBurst:
		s.coverBurstFill()
	case ObfsCoverIdleFill:
		s.coverIdleFill()
	case ObfsCoverAdaptiveEWMA:
		s.coverAdaptiveEWMA()
	}
}

// legacy periodic dummy fill (for compatibility)
func (s *ObfsConnState) coverDummyLegacy() {
	ticker := time.NewTicker(ObfsDefaultDummyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.coverStop:
			return
		case <-ticker.C:
			if mathrand.Float64() < ObfsDefaultDummyRatio {
				s.enqueueDummyPacket()
			}
		}
	}
}

// scheduled burst fill: periodically inject a burst of dummy packets
func (s *ObfsConnState) coverBurstFill() {
	ticker := time.NewTicker(ObfsBurstFillInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.coverStop:
			return
		case <-ticker.C:
			for i := 0; i < ObfsBurstFillCount; i++ {
				s.enqueueDummyPacket()
			}
		}
	}
}

// idle fill: if应用层长期无流量，则以较短周期持续填充
func (s *ObfsConnState) coverIdleFill() {
	ticker := time.NewTicker(ObfsIdleFillInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.coverStop:
			return
		case <-ticker.C:
			s.coverMu.RLock()
			idle := time.Since(s.lastSent)
			s.coverMu.RUnlock()
			if idle > 2*ObfsIdleFillInterval {
				s.enqueueDummyPacket()
			}
		}
	}
}

// EWMA-adaptive fill:自适应填充流量，确保填充流量与实际应用流量比例达标
func (s *ObfsConnState) coverAdaptiveEWMA() {
	fillTarget := 8000.0 // 最低目标带宽，字节/采样周期
	s.adaptiveEWMA.alpha = ObfsEWMAAlpha
	ticker := time.NewTicker(ObfsIdleFillInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.coverStop:
			return
		case <-ticker.C:
			s.coverMu.RLock()
			real := s.appBytesEWMA.Value()
			s.coverMu.RUnlock()
			// 目标：保证每采样周期总流量大于fillTarget
			if real < fillTarget {
				needed := int((fillTarget - real) / float64(ObfsMaxFrag))
				for i := 0; i < needed; i++ {
					s.enqueueDummyPacket()
				}
			}
		}
	}
}

// enqueueDummyPacket pushes a dummy packet for immediate send.
func (s *ObfsConnState) enqueueDummyPacket() {
	dummy := s.makeDummyPacket()
	if dummy == nil {
		return
	}
	s.writeMu.Lock()
	if !s.writeClosed {
		pkt := obfsPacket{
			hdr:    obfsHeader{}, // header already in dummy
			data:   dummy,
			sentAt: time.Now(),
		}
		heap.Push(&s.writeQueue, pkt)
		s.writeCond.Signal()
	}
	s.writeMu.Unlock()
}

// FeedInput buffers new obfs-protocol plaintext data into the state.
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
func (s *ObfsConnState) ReadObfs(b []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
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
		_, _ = s.readBuf.Read(make([]byte, ObfsHeaderLen))
		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(&s.readBuf, payload); err != nil {
				return 0, err
			}
		}
		paddingToSkip := totalLen - ObfsHeaderLen - payloadLen
		if paddingToSkip > 0 {
			_, _ = s.readBuf.Read(make([]byte, paddingToSkip))
		}
		if flags&ObfsFlagDummy != 0 {
			continue
		}
		if seq == s.seqRead {
			n := copy(b, payload)
			s.seqRead++
			return n, nil
		}
		if seq > s.seqRead && seq-s.seqRead < ObfsMaxSkew {
			s.readReorder[seq] = payload
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
	}
}

// CloseRead marks the receive-side as closed.
func (s *ObfsConnState) CloseRead() {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.readClosed = true
}
