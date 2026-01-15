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
	"errors"
	"golang.org/x/sync/singleflight"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/scionproto/scion/pkg/stun"
)

const timeoutDuration = 5 * time.Minute

// stunConn is a wrapper around sysPacketConn that handles STUN requests.
type stunConn struct {
	sysPacketConn
	recvChan       chan dataPacket
	maxQueuedBytes int64
	mutex          sync.Mutex
	sg             singleflight.Group

	// the following fields are protected by mutex
	queuedBytes          int64
	stunChans            map[stun.TxID]chan stunResponse
	mappings             map[netip.AddrPort]*natMapping
	readDeadline         time.Time
	writeDeadline        time.Time
	readDeadlineChanged  chan struct{}
	writeDeadlineChanged chan struct{}
	cond                 *sync.Cond // condition variable for pending STUN requests
}

type dataPacket struct {
	data []byte
	addr net.Addr
}

type stunResponse struct {
	addr netip.AddrPort
	err  error
}

func newSTUNConn(conn sysPacketConn) (*stunConn, error) {
	// Get the receive buffer size
	sysCallConn, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var rcvBufSize int
	err = sysCallConn.Control(func(fd uintptr) {
		rcvBufSize, err = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	})
	if err != nil {
		return nil, err
	}

	// assuming lower bound of per packet metadata of 64 bytes
	maxNumPacket := max(rcvBufSize/64, 10)

	c := &stunConn{
		sysPacketConn:        conn,
		recvChan:             make(chan dataPacket, maxNumPacket),
		maxQueuedBytes:       int64(rcvBufSize),
		stunChans:            make(map[stun.TxID]chan stunResponse),
		mappings:             make(map[netip.AddrPort]*natMapping),
		readDeadlineChanged:  make(chan struct{}),
		writeDeadlineChanged: make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mutex)

	// background goroutine to continuously read from the underlying UDP connection and filter out
	// STUN packets
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := c.sysPacketConn.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) ||
					errors.Is(err, syscall.EBADF) { // bad file descriptor (connection closed)
					close(c.recvChan)
					return
				}
				continue
			}
			respTxID, mappedAddr, err := stun.ParseResponse(buf[:n])
			if err == nil {
				c.mutex.Lock()
				ch, ok := c.stunChans[respTxID]
				c.mutex.Unlock()
				if ok {
					select {
					case ch <- stunResponse{addr: mappedAddr, err: err}:
					default:
					}
				}
			} else if errors.Is(err, stun.ErrNotSTUN) {
				func() {
					c.mutex.Lock()
					defer c.mutex.Unlock()

					pktLen := int64(len(buf[:n]))
					if c.queuedBytes+pktLen <= c.maxQueuedBytes {
						data := make([]byte, n)
						copy(data, buf[:n])
						select {
						case c.recvChan <- dataPacket{data: data, addr: addr}:
							c.queuedBytes += pktLen
						default:
						}
					}
				}()
			} // for all other errors, ignore the packet
		}
	}()

	return c, nil
}

func (c *stunConn) ReadFrom(b []byte) (int, net.Addr, error) {
	deadlineTimer := time.NewTimer(0)
	deadlineTimer.Stop()

	for {
		c.mutex.Lock()
		deadline := c.readDeadline
		deadlineChan := c.readDeadlineChanged
		c.mutex.Unlock()

		if !deadline.IsZero() {
			timeout := time.Until(deadline)
			if timeout <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			deadlineTimer.Reset(timeout)
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
		case <-deadlineTimer.C:
			return 0, nil, os.ErrDeadlineExceeded
		case <-deadlineChan:
			continue // read deadline changed, re-evaluate
		}
	}
}

type natMapping struct {
	destination netip.AddrPort
	mappedAddr  netip.AddrPort
	lastUsed    time.Time
}

func (mapping *natMapping) touch() {
	mapping.lastUsed = time.Now()
}

func (mapping *natMapping) isValid() bool {
	return time.Since(mapping.lastUsed) < timeoutDuration
}

func (c *stunConn) mappedAddr(dest netip.AddrPort) (netip.AddrPort, error) {
	addr, exists := func() (netip.AddrPort, bool) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		// Check if mapping exists and is valid
		if mapping, ok := c.mappings[dest]; ok && mapping.isValid() {
			mapping.touch()
			return mapping.mappedAddr, true
		}
		return netip.AddrPort{}, false
	}()
	if exists {
		return addr, nil
	}

	result, err, _ := c.sg.Do(dest.String(), func() (interface{}, error) {
		return c.makeSTUNRequest(dest)
	})

	if err != nil {
		return netip.AddrPort{}, err
	}

	return result.(*natMapping).mappedAddr, nil
}

func (c *stunConn) makeSTUNRequest(dest netip.AddrPort) (*natMapping, error) {
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
	c.mutex.Unlock()

	defer func() {
		c.mutex.Lock()
		delete(c.stunChans, txID)
		c.mutex.Unlock()
	}()

	retransmissionTimer := time.NewTimer(0)
	retransmissionTimer.Stop()

	deadlineTimer := time.NewTimer(0)
	deadlineTimer.Stop()

	var mappedAddr netip.AddrPort
	currentRTO := initialRTO

	for i := range Rc {
		_, err := c.WriteTo(stunRequest, net.UDPAddrFromAddrPort(dest))
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
		retransmissionTimer.Reset(waitDuration)

		var timerExpired bool
		for !timerExpired {
			c.mutex.Lock()
			deadline := c.writeDeadline
			deadlineChanged := c.writeDeadlineChanged
			c.mutex.Unlock()

			if !deadline.IsZero() {
				timeout := time.Until(deadline)
				if timeout <= 0 {
					return nil, os.ErrDeadlineExceeded
				}
				deadlineTimer.Reset(timeout)
			}

			select {
			case <-retransmissionTimer.C:
				timerExpired = true
			case <-deadlineTimer.C:
				return nil, os.ErrDeadlineExceeded
			case <-deadlineChanged:
				continue // write deadline changed, re-evaluate
			case resp := <-stunChan:
				if resp.err != nil {
					return nil, resp.err
				}
				mappedAddr = resp.addr
				if !mappedAddr.IsValid() {
					return nil, errors.New("invalid mapped address")
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
		}
	}

	return nil, errors.New("STUN request timed out")
}

func (c *stunConn) SetDeadline(t time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	err := c.sysPacketConn.SetWriteDeadline(t)
	if err == nil {
		c.readDeadline = t
		c.writeDeadline = t
		close(c.readDeadlineChanged)
		close(c.writeDeadlineChanged)
		c.readDeadlineChanged = make(chan struct{})
		c.writeDeadlineChanged = make(chan struct{})
	}
	return err
}

func (c *stunConn) SetReadDeadline(t time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.readDeadline = t
	close(c.readDeadlineChanged)
	c.readDeadlineChanged = make(chan struct{})
	return nil
}

func (c *stunConn) SetWriteDeadline(t time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	err := c.sysPacketConn.SetWriteDeadline(t)
	if err == nil {
		c.writeDeadline = t
		close(c.writeDeadlineChanged)
		c.writeDeadlineChanged = make(chan struct{})
	}
	return err
}

func (c *SCIONPacketConn) isSTUNConn() bool {
	_, ok := c.conn.(*stunConn)
	return ok
}
