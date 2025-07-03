package tls

import (
	"bytes"
	"container/heap"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	mathrand "math/rand"
	"sync"
	"time"
)

// =====================
// 常量及基础结构体
// =====================

const (
	ObfsMagic      = 0x4D58
	ObfsVersion    = 0x03
	ObfsHeaderLen  = 24 // Magic(2) + Version(1) + Flags(1) + Seq(4) + Timestamp(8) + RandID(4) + PayloadLen(2) + TotalLen(2)
	ObfsMinFrag    = 800
	ObfsMaxFrag    = 1200
	ObfsMaxDelay   = 350 * time.Millisecond
	ObfsMaxSkew    = 8 // 乱序缓冲窗口
	ObfsDummyRatio = 0.25
	ObfsDummyInterval = 180 * time.Millisecond
)

const (
	ObfsFlagDummy = 0x01
)

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

type obfsPacket struct {
	hdr    obfsHeader
	data   []byte
	sentAt time.Time // 调度时间
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

// =====================
// ObfsConnState 结构体
// =====================

type ObfsConnState struct {
	// 写方向
	seqWrite    uint32
	writeQueue  obfsPacketHeap
	writeMu     sync.Mutex
	writeCond   *sync.Cond
	netWriter   func([]byte) error
	stopCh      chan struct{}
	writeClosed bool

	// 读方向
	seqRead      uint32
	readBuf      bytes.Buffer
	readReorder  map[uint32][]byte
	readMu       sync.Mutex
	readClosed   bool
}

// =====================
// 初始化
// =====================

func NewObfsConnState(netWriter func([]byte) error) *ObfsConnState {
	s := &ObfsConnState{
		netWriter:  netWriter,
		stopCh:     make(chan struct{}),
		readReorder: make(map[uint32][]byte),
	}
	s.writeCond = sync.NewCond(&s.writeMu)
	go s.asyncSender()
	go s.periodicDummySender()
	return s
}

// =====================
// 写方向：入队
// =====================

func (s *ObfsConnState) WriteObfs(b []byte) (int, error) {
	if s.writeClosed {
		return 0, errors.New("obfs: write closed")
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
			rand.Read(pad)
			buf = append(buf, pad...)
		}

		// 写入异步池
		s.writeMu.Lock()
		// 随机delay (正态分布)
		delay := time.Duration(math.Abs(mathrand.NormFloat64() * float64(ObfsMaxDelay/6)))
		if delay > ObfsMaxDelay {
			delay = ObfsMaxDelay
		}
		schAt := time.Now().Add(delay)
		pkt := obfsPacket{hdr: h, data: buf, sentAt: schAt}
		heap.Push(&s.writeQueue, pkt)
		s.writeCond.Signal()
		s.writeMu.Unlock()
	}
	return total, nil
}

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

// =====================
// 写方向：异步调度
// =====================

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
		// 取最早的包
		pkt := heap.Pop(&s.writeQueue).(obfsPacket)
		now := time.Now()
		wait := pkt.sentAt.Sub(now)
		s.writeMu.Unlock()
		if wait > 0 {
			time.Sleep(wait)
		}
		// 真正写到网络
		_ = s.netWriter(pkt.data)
	}
}

// =====================
// 写方向：定时伪装包
// =====================

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
	rand.Read(buf[ObfsHeaderLen:])
	s.writeMu.Lock()
	pkt := obfsPacket{hdr: h, data: buf, sentAt: time.Now()}
	heap.Push(&s.writeQueue, pkt)
	s.writeCond.Signal()
	s.writeMu.Unlock()
}

// =====================
// 读方向：输入
// =====================

func (s *ObfsConnState) FeedInput(data []byte) {
	s.readBuf.Write(data)
}

// =====================
// 读方向：解包与乱序重组
// =====================

func (s *ObfsConnState) ReadObfs(b []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
		// 查找readBuf是否有完整obfs包头
		if s.readBuf.Len() < ObfsHeaderLen {
			return 0, nil // 需要上层补充更多数据
		}
		head := s.readBuf.Bytes()[:ObfsHeaderLen]
		if binary.BigEndian.Uint16(head[0:2]) != ObfsMagic {
			return 0, errors.New("obfs: bad magic")
		}
		flags := head[3]
		seq := binary.BigEndian.Uint32(head[4:8])
		payloadLen := int(binary.BigEndian.Uint16(head[20:22]))
		totalLen := int(binary.BigEndian.Uint16(head[22:24]))

		if s.readBuf.Len() < totalLen {
			return 0, nil // 需要上层补充更多数据
		}
		// 完整包体
		s.readBuf.Next(ObfsHeaderLen)
		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			s.readBuf.Read(payload)
		}
		s.readBuf.Next(totalLen - ObfsHeaderLen - payloadLen) // 丢弃填充

		// dummy包直接丢弃
		if flags&ObfsFlagDummy != 0 {
			continue
		}
		// 乱序重组
		if seq == s.seqRead {
			n := copy(b, payload)
			s.seqRead++
			return n, nil
		} else if seq > s.seqRead && seq-s.seqRead < ObfsMaxSkew {
			// 缓存未来包
			s.readReorder[seq] = payload
			// 检查有无下一个应到
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
			continue // 继续读下一个包
		}
		// 旧包丢弃
	}
}

func (s *ObfsConnState) CloseRead() {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.readClosed = true
}
