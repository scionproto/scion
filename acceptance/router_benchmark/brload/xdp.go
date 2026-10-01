// Copyright 2026 SCION Association
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux && (amd64 || arm64)

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/underlay/afxdp"
)

// pacer is a per-worker, absolute-deadline rate limiter: it advances a virtual
// "next send" time by want*interval per batch, so an oversleeping Sleep shortens
// the next wait instead of losing budget (a token bucket would clip it). This
// holds the target rate even at multi-100k pps, where OS timer resolution is coarse.
type pacer struct {
	interval float64 // seconds per packet
	next     time.Time
}

func newPacer(ratePerSec float64) *pacer {
	return &pacer{interval: 1.0 / ratePerSec}
}

// acquire blocks until it is time to send the next want packets and returns want.
func (p *pacer) acquire(want int) int {
	now := time.Now()
	if p.next.IsZero() {
		p.next = now
	}
	if d := p.next.Sub(now); d > 0 {
		time.Sleep(d)
	}
	p.next = p.next.Add(time.Duration(float64(want) * p.interval * float64(time.Second)))
	// If we have fallen more than a few ms behind (e.g. a scheduling stall),
	// resync to now so we pace forward rather than bursting to catch up.
	if time.Since(p.next) > 5*time.Millisecond {
		p.next = time.Now()
	}
	return want
}

// txWorker drives one AF_XDP socket on one NIC TX queue from one goroutine.
type txWorker struct {
	sock        *afxdp.Socket
	cpu         int
	numStreams  uint32
	startStream uint32
	flowIDOff   int
	v6          bool // recompute the UDP checksum per packet (IPv6 mandates it)
	pktLen      uint32
	batchSize   int
	limiter     *pacer // nil = unlimited
	// templates holds more than one frame template only in mix mode: the worker
	// copies the next template into each frame round-robin. nil or len 1: the
	// prefilled template is reused with no per-frame copy.
	templates [][]byte
	sent      atomic.Uint64
}

// xdpSender fans packet generation out across several TX queues/cores.
type xdpSender struct {
	iface   *afxdp.Interface
	workers []*txWorker
	stop    atomic.Bool
	total   atomic.Uint64
	maxPkts uint64
	wg      sync.WaitGroup
}

// detectTxQueues counts the NIC's TX queues from sysfs.
func detectTxQueues(dev string) (int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/sys/class/net/%s/queues", dev))
	if err != nil {
		return 0, serrors.Wrap("reading NIC queues from sysfs", err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "tx-") {
			n++
		}
	}
	if n == 0 {
		n = 1
	}
	return n, nil
}

// newXdpSender opens one TX-only AF_XDP socket per queue on devName and prepares
// the workers. template is a full Ethernet+IP+UDP+SCION frame whose outer UDP
// checksum has already been zeroed; workers patch only the SCION flow ID per
// packet (and, for IPv6, recompute the UDP checksum).
func newXdpSender(devName string, template []byte, cfg xdpConfig) (*xdpSender, error) {
	return newXdpSenderMulti(devName, [][]byte{template}, cfg)
}

// newXdpSenderMulti is [newXdpSender] with several frame templates on one device,
// each worker cycling them round-robin. Used by the mix case to inject different
// forwarding patterns on one ingress link.
// Requirement: all templates share one length (one packet size and IP version,
// hence one flow-ID offset and TX length).
func newXdpSenderMulti(devName string, templates [][]byte, cfg xdpConfig) (*xdpSender, error) {
	if cfg.numStreams == 0 {
		return nil, serrors.New("num-streams must be >= 1")
	}
	if len(templates) == 0 {
		return nil, serrors.New("at least one template is required")
	}
	template := templates[0]
	for _, t := range templates {
		if len(t) != len(template) {
			return nil, serrors.New("mixed-traffic templates must share one length",
				"first", len(template), "other", len(t))
		}
	}
	// Copy mode only with more than one template; the single-template path keeps
	// its prefill-only loop with no per-frame copy.
	var multi [][]byte
	if len(templates) > 1 {
		multi = templates
	}

	txQueues := cfg.txQueues
	if txQueues <= 0 {
		detected, err := detectTxQueues(devName)
		if err != nil {
			return nil, err
		}
		txQueues = detected
		if gm := runtime.GOMAXPROCS(0); txQueues > gm {
			txQueues = gm
		}
	}

	frameSize := cfg.frameSize
	if frameSize == 0 {
		frameSize = afxdp.DefaultFrameSize
	}
	if int(frameSize)-afxdp.TxMetadataLen < len(template) {
		return nil, serrors.New("packet larger than UMEM frame",
			"packet", len(template), "frame_size", frameSize, "tx_metadata", afxdp.TxMetadataLen)
	}

	batchSize := cfg.batchSize
	if batchSize == 0 {
		batchSize = afxdp.DefaultBatchSize
	}

	offsets := underlayOffsetsOf(template)

	// Resolve the effective global packet rate from the pps and bitrate caps
	// (the tighter of the two wins), then split it evenly across workers.
	globalPPS := effectiveMaxPPS(cfg.maxPPS, cfg.maxMbps, len(template))

	iface, err := afxdp.NewTxInterface(devName)
	if err != nil {
		return nil, serrors.Wrap("resolving TX interface", err)
	}

	s := &xdpSender{iface: iface}
	if cfg.maxPackets > 0 {
		s.maxPkts = uint64(cfg.maxPackets)
	}

	for i := range txQueues {
		queueID := uint32(cfg.firstQueue + i)
		sock, err := afxdp.Open(afxdp.SocketConfig{
			QueueID:   queueID,
			TxOnly:    true,
			NumFrames: cfg.numFrames,
			FrameSize: cfg.frameSize,
			TxSize:    cfg.txRing,
			BatchSize: batchSize,
		}, iface, cfg.preferHugepages, cfg.preferZerocopy)
		if err != nil {
			s.closeSockets()
			iface.Close()
			return nil, serrors.Wrap("opening AF_XDP TX socket", err,
				"queue", queueID, "hint", "check --tx-queues vs NIC queue count")
		}
		sock.PrefillTx(template)
		log.Info("AF_XDP TX socket ready",
			"device", devName, "queue", queueID,
			"zerocopy", sock.IsZerocopy(), "hugepages", sock.IsHugepages())

		var limiter *pacer
		if globalPPS > 0 {
			limiter = newPacer(globalPPS / float64(txQueues))
		}
		s.workers = append(s.workers, &txWorker{
			sock:        sock,
			cpu:         cfg.cpuOffset + i,
			numStreams:  uint32(cfg.numStreams),
			startStream: uint32(i) * uint32(cfg.numStreams) / uint32(txQueues),
			flowIDOff:   offsets.flowID,
			v6:          isIPv6(template),
			pktLen:      uint32(len(template)),
			batchSize:   int(batchSize),
			limiter:     limiter,
			templates:   multi,
		})
	}

	log.Info("AF_XDP sender configured",
		"tx_queues", txQueues,
		"num_streams", cfg.numStreams,
		"max_pps", cfg.maxPPS,
		"max_mbps", cfg.maxMbps,
		"effective_pps", uint64(globalPPS))
	return s, nil
}

// effectiveMaxPPS converts the pps and bitrate caps into a single packets/sec
// target (0 = unlimited). wireBytes approximates the on-wire size including
// preamble (8), inter-frame gap (12) and FCS (4).
func effectiveMaxPPS(maxPPS, maxMbps uint64, pktLen int) float64 {
	var pps float64
	if maxPPS > 0 {
		pps = float64(maxPPS)
	}
	if maxMbps > 0 {
		wireBits := float64(pktLen+24) * 8
		fromBps := float64(maxMbps) * 1e6 / wireBits
		if pps == 0 || fromBps < pps {
			pps = fromBps
		}
	}
	return pps
}

// start launches all worker goroutines.
func (s *xdpSender) start() {
	s.wg.Add(len(s.workers))
	for _, w := range s.workers {
		go s.runWorker(w)
	}
}

// wait blocks until the duration elapses or the packet cap is hit, then signals
// workers to stop and joins them.
func (s *xdpSender) wait(duration time.Duration) {
	deadline := time.Now().Add(duration)
	for !s.stop.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	s.stop.Store(true)
	s.wg.Wait()
}

// sent returns the total number of packets transmitted across all workers.
func (s *xdpSender) sent() uint64 {
	var total uint64
	for _, w := range s.workers {
		total += w.sent.Load()
	}
	return total
}

// close joins any remaining workers and releases all sockets and the interface.
// Sockets are closed only after workers have stopped so no goroutine touches
// unmapped UMEM.
func (s *xdpSender) close() {
	s.stop.Store(true)
	s.wg.Wait()
	s.closeSockets()
	if s.iface != nil {
		s.iface.Close()
		s.iface = nil
	}
}

func (s *xdpSender) closeSockets() {
	for _, w := range s.workers {
		if w.sock != nil {
			w.sock.Close()
			w.sock = nil
		}
	}
}

// runWorker is the per-queue hot loop. It pins itself to a CPU, then transmits
// batches, patching the outer UDP source port and SCION flow ID of each frame.
func (s *xdpSender) runWorker(w *txWorker) {
	defer s.wg.Done()
	defer log.HandlePanic()

	// Pin this goroutine's OS thread to a dedicated CPU. Best effort: pinning
	// failures are logged but not fatal. We never UnlockOSThread so the thread
	// is discarded when the worker returns.
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Zero()
	set.Set(w.cpu)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		log.Info("CPU pinning failed (continuing unpinned)", "cpu", w.cpu, "err", err)
	}

	stream := w.startStream
	tmplIdx := 0
	for !s.stop.Load() {
		n := w.batchSize
		if w.limiter != nil {
			n = w.limiter.acquire(n)
		}
		submitted := 0
		for range n {
			f := w.sock.NextFrame()
			if f.Buf == nil {
				w.sock.PollCompletions(uint32(w.batchSize))
				f = w.sock.NextFrame()
				if f.Buf == nil {
					break // freelist still empty; flush and retry next round
				}
			}
			// Mix mode: overwrite the frame with the next template so one queue
			// emits every forwarding pattern. Single-template mode leaves the
			// prefilled frame untouched.
			if w.templates != nil {
				copy(f.Buf[:w.pktLen], w.templates[tmplIdx])
				tmplIdx++
				if tmplIdx >= len(w.templates) {
					tmplIdx = 0
				}
			}
			binary.BigEndian.PutUint16(f.Buf[w.flowIDOff:], uint16(stream))
			if w.v6 {
				// IPv6 requires a valid, non-zero UDP checksum; the flow-ID
				// patch above changed the payload, so recompute it.
				writeUDP6Checksum(f.Buf[:w.pktLen])
			}
			if err := w.sock.Submit(f.Addr, w.pktLen); err != nil {
				log.Error("AF_XDP submit failed", "err", err)
				s.stop.Store(true)
				break
			}
			submitted++
			stream++
			if stream >= w.numStreams {
				stream = 0
			}
		}
		if submitted > 0 {
			if err := w.sock.FlushTx(); err != nil {
				log.Error("AF_XDP flush failed", "err", err)
				s.stop.Store(true)
			}
			w.sent.Add(uint64(submitted))
			if s.maxPkts > 0 && s.total.Add(uint64(submitted)) >= s.maxPkts {
				s.stop.Store(true)
			}
		}
		w.sock.PollCompletions(uint32(w.batchSize))
	}
}

// writeUDP6Checksum recomputes and writes the UDP checksum of an
// Ethernet(14)+IPv6(40)+UDP frame in place. IPv6 mandates a non-zero UDP
// checksum (RFC 8200); a kernel-socket underlay drops datagrams that carry a
// zero checksum, so the AF_XDP generator must fill it in for every v6 packet.
func writeUDP6Checksum(frame []byte) {
	const ipOff = 14
	const udpOff = ipOff + 40
	if len(frame) < udpOff+8 {
		return
	}
	udpLen := int(binary.BigEndian.Uint16(frame[udpOff+4 : udpOff+6]))
	frame[udpOff+6] = 0
	frame[udpOff+7] = 0

	var sum uint32
	// Pseudo-header: 16-byte src + 16-byte dst addresses.
	for i := ipOff + 8; i < ipOff+40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(frame[i:]))
	}
	sum += uint32(udpLen) // upper-layer packet length
	sum += 17             // next header = UDP

	// UDP header + payload.
	end := min(udpOff+udpLen, len(frame))
	i := udpOff
	for ; i+1 < end; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(frame[i:]))
	}
	if i < end { // trailing odd byte
		sum += uint32(frame[i]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xFFFF // a transmitted UDP checksum of 0 is forbidden for IPv6
	}
	binary.BigEndian.PutUint16(frame[udpOff+6:], csum)
}
