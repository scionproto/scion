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
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/scionproto/scion/pkg/stun"
)

const timeoutDuration = 5 * time.Minute

// stunHandler is a wrapper around net.UDPConn that handles STUN requests.
type stunHandler struct {
	*net.UDPConn
	recvChan       chan bufferedPacket
	maxQueuedBytes int64
	mutex          sync.Mutex

	// the following fields are protected by mutex
	queuedBytes     int64
	stunChans       map[stun.TxID]chan stunResponse
	mappings        map[*net.UDPAddr]*natMapping
	pendingRequests map[*net.UDPAddr]bool
	writeDeadline   time.Time
	readDeadline    time.Time
	cond            *sync.Cond // condition variable for pending STUN requests
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
		UDPConn:         conn,
		recvChan:        make(chan bufferedPacket, maxNumPacket),
		maxQueuedBytes:  int64(rcvBufSize),
		stunChans:       make(map[stun.TxID]chan stunResponse),
		mappings:        make(map[*net.UDPAddr]*natMapping),
		pendingRequests: make(map[*net.UDPAddr]bool),
	}
	handler.cond = sync.NewCond(&handler.mutex)

	// background goroutine to continuously read from the underlying UDP connection and filter out
	// STUN packets
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := handler.UDPConn.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) ||
					errors.Is(err, syscall.EBADF) { // bad file descriptor (connection closed)
					close(handler.recvChan)
					return
				}
				continue
			}

			data := make([]byte, n)
			copy(data, buf[:n])

			if stun.Is(data) {
				respTxID, mappedAddr, err := stun.ParseResponse(data)
				if err != nil {
					continue
				}
				handler.mutex.Lock()
				ch, ok := handler.stunChans[respTxID]
				handler.mutex.Unlock()
				if ok {
					select {
					case ch <- stunResponse{mappedAddr: mappedAddr, err: err}:
					default:
					}
				}
			} else {
				handler.queuePacket(bufferedPacket{data: data, addr: addr})
			}
		}
	}()

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

func (c *stunHandler) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mutex.Lock()
	deadline := c.readDeadline
	c.mutex.Unlock()

	var timeoutChan <-chan time.Time
	if !deadline.IsZero() {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timeoutChan = time.After(timeout)
	} else {
		timeoutChan = nil // no timeout
	}
	select {
	case pkt, ok := <-c.recvChan:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		c.mutex.Lock()
		c.queuedBytes -= int64(len(pkt.data))
		c.mutex.Unlock()
		n := copy(b, pkt.data)
		return n, pkt.addr, nil
	case <-timeoutChan:
		return 0, nil, os.ErrDeadlineExceeded
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

func (c *stunHandler) makeStunRequest(dest *net.UDPAddr) (*natMapping, error) {
	txID := stun.NewTxID()
	stunRequest := stun.Request(txID)

	// values according to RFC 8489 Section 6.2.1
	// TODO: make configurable?
	const Rc = 7  // Maximum number of retransmissions
	const Rm = 16 // Multiplier for final retransmission wait time
	const initialRTO = 500 * time.Millisecond

	c.mutex.Lock()
	stunChan := make(chan stunResponse, Rc*2)
	c.stunChans[txID] = stunChan

	ctx := context.Background()
	var cancel context.CancelFunc
	if !c.writeDeadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, c.writeDeadline)
		defer cancel()
	}

	c.mutex.Unlock()

	defer func() {
		c.mutex.Lock()
		delete(c.stunChans, txID)
		c.mutex.Unlock()
	}()

	var mappedAddress netip.AddrPort
	currentRTO := initialRTO

STUNLoop:
	for i := 0; i < Rc; i++ {
		_, err := c.WriteTo(stunRequest, dest)
		if err != nil {
			return nil, err
		}

		var waitDuration time.Duration
		if i < Rc-1 {
			waitDuration = currentRTO
			currentRTO *= 2
		} else {
			waitDuration = Rm * initialRTO
		}

		select {
		case <-time.After(waitDuration):
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		case resp := <-stunChan:
			if resp.err != nil {
				return nil, resp.err
			}
			mappedAddress = resp.mappedAddr
			break STUNLoop
		}
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

	c.mutex.Unlock()
	return mapping, nil
}

func (c *stunHandler) SetDeadline(t time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return c.UDPConn.SetDeadline(t)
}

func (c *stunHandler) SetReadDeadline(t time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.readDeadline = t
	return c.UDPConn.SetReadDeadline(t)
}

func (c *stunHandler) SetWriteDeadline(t time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.writeDeadline = t
	return c.UDPConn.SetWriteDeadline(t)
}
