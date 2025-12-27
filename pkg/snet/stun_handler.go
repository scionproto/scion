// Copyright 2025 ETH Zurich
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

package snet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/pkg/stun"
)

const timeoutDuration = 5 * time.Minute

// stunHandler is a wrapper around net.UDPConn that handles STUN requests.
type stunHandler struct {
	*net.UDPConn
	recvChan       chan bufferedPacket
	maxQueuedBytes int64
	recvStunChan   chan []byte
	mutex          sync.Mutex

	// the following fields are protected by mutex
	queuedBytes          int64
	stunChans            map[stun.TxID]chan stunResponse
	mappings             map[*net.UDPAddr]*natMapping
	retransmissionTimers map[*net.UDPAddr]*retransmissionTimer
	pendingRequests      map[*net.UDPAddr]bool
	writeDeadline        time.Time
	cond                 *sync.Cond // condition variable for pending STUN requests
}

type bufferedPacket struct {
	data []byte
	addr net.Addr
}

type stunResponse struct {
	mappedAddr netip.AddrPort
	err        error
}

func newSTUNHandler(conn *net.UDPConn) (*stunHandler, error) {
	// Get the receive buffer size
	fd, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	rcvBufSize, err := syscall.GetsockoptInt(int(fd.Fd()), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return nil, err
	}
	maxNumPacket := rcvBufSize / 64 // assuming lower bound of per packet metadata of 64 bytes
	if maxNumPacket < 10 {
		maxNumPacket = 10
	}

	handler := &stunHandler{
		UDPConn:              conn,
		recvChan:             make(chan bufferedPacket, maxNumPacket),
		maxQueuedBytes:       int64(rcvBufSize),
		recvStunChan:         make(chan []byte, 100),
		stunChans:            make(map[stun.TxID]chan stunResponse),
		mappings:             make(map[*net.UDPAddr]*natMapping),
		retransmissionTimers: make(map[*net.UDPAddr]*retransmissionTimer),
		pendingRequests:      make(map[*net.UDPAddr]bool),
	}
	handler.cond = sync.NewCond(&handler.mutex)
	return handler, nil
}

func (c *stunHandler) queuePacket(pkt bufferedPacket) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	pktLen := int64(len(pkt.data))

	if c.queuedBytes+pktLen > c.maxQueuedBytes {
		return false
	}

	select {
	case c.recvChan <- pkt:
		c.queuedBytes += pktLen
		return true
	default:
		return false
	}
}

func (c *stunHandler) dequeuePacket() (bufferedPacket, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	select {
	case pkt := <-c.recvChan:
		c.queuedBytes -= int64(len(pkt.data))
		return pkt, true
	default:
		return bufferedPacket{}, false
	}
}

func (c *stunHandler) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		pkt, ok := c.dequeuePacket()
		if ok {
			copy(b, pkt.data)
			return len(pkt.data), pkt.addr, nil
		}
		n, addr, err := c.UDPConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		if stun.Is(b) {
			bb := make([]byte, n)
			copy(bb, b[:n])
			select {
			case c.recvStunChan <- bb:
			default:
			}
		} else {
			return n, addr, nil
		}
	}
}

func (c *stunHandler) readStunPacket(ctx context.Context) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			select {
			case pkt := <-c.recvStunChan:
				return pkt, nil
			default:
				buf := make([]byte, 1500)
				n, addr, err := c.UDPConn.ReadFrom(buf)
				if err != nil {
					return nil, err
				}
				buf = buf[:n]
				if stun.Is(buf) {
					return buf, nil
				} else {
					c.queuePacket(bufferedPacket{data: buf[:n], addr: addr})
				}
			}
		}
	}
}

func (c *stunHandler) getStunResponse(ctx context.Context, txid stun.TxID) (netip.AddrPort, error) {
	c.mutex.Lock()
	ch, ok := c.stunChans[txid]
	c.mutex.Unlock()
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("STUN response channel not found")
	}
	for {
		select {
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		default:
			select {
			case resp := <-ch:
				return resp.mappedAddr, resp.err
			default:
				pkt, err := c.readStunPacket(ctx)
				if err != nil {
					return netip.AddrPort{}, err
				}
				respTxID, mappedAddr, err := stun.ParseResponse(pkt)
				if err != nil {
					continue
				}
				if respTxID == txid {
					return mappedAddr, nil
				}
				// Send to the appropriate channel
				c.mutex.Lock()
				ch, ok := c.stunChans[respTxID]
				c.mutex.Unlock()
				if ok {
					select {
					case ch <- stunResponse{mappedAddr: mappedAddr, err: err}:
					default:
					}
				}
			}
		}
	}
}

type natMapping struct {
	destination *net.UDPAddr
	mappedAddr  *net.UDPAddr
	lastUsed    time.Time
}

func (mapping *natMapping) touch() {
	mapping.lastUsed = time.Now()
}

func (mapping *natMapping) isValid() bool {
	return time.Since(mapping.lastUsed) < timeoutDuration
}

func (c *stunHandler) mappedAddr(dest *net.UDPAddr) (*net.UDPAddr, error) {
	c.mutex.Lock()
	for {
		// Check if mapping exists and is valid
		if mapping, ok := c.mappings[dest]; ok {
			if mapping.isValid() {
				mapping.touch()
				addr := mapping.mappedAddr
				c.mutex.Unlock()
				return addr, nil
			}
		}
		// Check if STUN request is already happening concurrently
		if c.pendingRequests[dest] {
			c.cond.Wait()
			continue // Re-check mapping
		}

		c.pendingRequests[dest] = true
		break
	}

	c.mutex.Unlock()
	mapping, err := c.makeStunRequest(dest)
	c.mutex.Lock()

	delete(c.pendingRequests, dest)
	c.cond.Broadcast()
	if err != nil {
		c.mutex.Unlock()
		return nil, err
	}
	addr := mapping.mappedAddr
	c.mutex.Unlock()
	return addr, nil
}

type retransmissionTimer struct {
	// See RFC 6298 for details on these fields
	srtt   time.Duration
	rttvar time.Duration
	rto    time.Duration

	lastUsed time.Time
}

func (c *stunHandler) makeStunRequest(dest *net.UDPAddr) (*natMapping, error) {
	txID := stun.NewTxID()
	stunRequest := stun.Request(txID)

	// values according to RFC 8489 Section 6.2.1
	// TODO: make configurable?
	const Rc = 7  // Maximum number of retransmissions
	const Rm = 16 // Multiplier for final retransmission wait time

	c.mutex.Lock()
	if c.retransmissionTimers[dest] == nil {
		c.retransmissionTimers[dest] = &retransmissionTimer{
			srtt:     0,
			rttvar:   0,
			rto:      500 * time.Millisecond, // RFC8489 Section 6.2.1
			lastUsed: time.Now(),
		}
	}

	retransmissionTimer := c.retransmissionTimers[dest]

	// Reset timer if it hasn't been used for 10 minutes (RFC 8489 Section 6.2.1)
	if time.Since(retransmissionTimer.lastUsed) > 10*time.Minute {
		retransmissionTimer.rto = 500 * time.Millisecond
		retransmissionTimer.srtt = 0
		retransmissionTimer.rttvar = 0
	}

	c.stunChans[txID] = make(chan stunResponse, Rc*2)

	var ctx context.Context
	var cancel context.CancelFunc

	if c.writeDeadline.IsZero() {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithDeadline(context.Background(), c.writeDeadline)
	}
	g, ctx := errgroup.WithContext(ctx)

	c.mutex.Unlock()

	defer func() {
		c.mutex.Lock()
		delete(c.stunChans, txID)
		c.mutex.Unlock()
	}()

	isRetransmission := atomic.Bool{}
	isRetransmission.Store(false)

	var mappedAddress netip.AddrPort
	var startTime, endTime time.Time

	// Sending goroutine
	g.Go(func() error {
		originalRTO := retransmissionTimer.rto
		currentRTO := originalRTO
		startTime = time.Now()
		for i := 0; i < Rc; i++ {
			_, err := c.WriteTo(stunRequest, dest)
			if err != nil {
				return err
			}

			if i == 1 {
				isRetransmission.Store(true)
			}

			var waitDuration time.Duration
			if i < Rc-1 {
				waitDuration = currentRTO
				currentRTO *= 2
			} else {
				waitDuration = Rm * originalRTO
			}

			select {
			case <-time.After(waitDuration):
				// Continue to next iteration or timeout
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return context.DeadlineExceeded
	})

	// Receiving goroutine
	g.Go(func() error {
		var err error
		mappedAddress, err = c.getStunResponse(ctx, txID)
		cancel()
		if err != nil {
			return err
		}
		endTime = time.Now()
		return nil
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return nil, err
	}

	mappedAddr, err := net.ResolveUDPAddr("udp", mappedAddress.String())
	if err != nil {
		return nil, err
	}

	c.mutex.Lock()
	mapping := c.mappings[dest]
	if mapping == nil {
		mapping = &natMapping{destination: dest}
		c.mappings[dest] = mapping
	}
	mapping.mappedAddr = mappedAddr
	mapping.touch()

	// Skip RTT calculation on retransmission or error
	if isRetransmission.Load() || endTime.IsZero() {
		c.mutex.Unlock()
		return mapping, nil
	}

	// Update retransmission timer based on measured RTT, see RFC 6298
	rtt := endTime.Sub(startTime)
	if retransmissionTimer.srtt == 0 {
		retransmissionTimer.srtt = rtt
		retransmissionTimer.rttvar = rtt / 2
	} else {
		srttDiff := retransmissionTimer.srtt - rtt
		if srttDiff < 0 {
			srttDiff = -srttDiff
		}
		retransmissionTimer.rttvar = (3*retransmissionTimer.rttvar + srttDiff) / 4
		retransmissionTimer.srtt = (7*retransmissionTimer.srtt + rtt) / 8
	}
	maxTerm := retransmissionTimer.rttvar * 4
	if maxTerm < time.Millisecond {
		maxTerm = time.Millisecond
	}
	retransmissionTimer.rto = retransmissionTimer.srtt + maxTerm
	retransmissionTimer.lastUsed = time.Now()
	c.mutex.Unlock()
	return mapping, nil
}

func (c *stunHandler) SetWriteDeadline(t time.Time) error {
	c.mutex.Lock()
	c.writeDeadline = t
	c.mutex.Unlock()
	return c.UDPConn.SetWriteDeadline(t)
}
