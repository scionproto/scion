// Copyright 2017 ETH Zurich
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

// package rpt (Reliable Packet Transport) implements a simple packet-oriented
// protocol with ACKs on top of net.PacketConn.
package rpt

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	liblog "github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/util/bufpool"
)

// FIXME(scrye): move this to go/lib/infra/transport once it can import snet
// without causing a circular dependency.

type rptFlag uint8

func (f rptFlag) isSet(other rptFlag) bool {
	return f&other != 0
}

// Protocol constants.
const (
	// Flag field set in sent messages that do not require ACK.
	flagsNone = rptFlag(0x00)
	// Included in sent messages that require ACK.
	flagNeedACK = rptFlag(0x01)
	// Included in ACKs.
	flagACK = rptFlag(0x02)
	// Size of RPT header.
	rptHdrLen = 8
	// Maximum amount of time to try and put an ACK on the network
	rptACKTimeout = 2 * time.Second
	// If no ACK is received, senders will resend the message every
	// rptRetryTimeout seconds for as long as the context is not canceled.
	rptRetryTimeout = 2 * time.Second
)

// Internal constants
const (
	maxReadEvents = 1 << 8
)

var (
	// Used to initialize the first packet ID
	generator = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
)

var _ infra.Transport = (*RPT)(nil)

// RPT (Reliable Packet Transport) implements a simple packet-oriented protocol
// with ACKs on top of net.PacketConn.
//
// Two sending primitives are available:
//
// SendUnreliableMsgTo sends a message and returns without waiting for an ACK.
//
// SendMsgTo sends a message and waits for a limited amount of time for an
// ACK; if time allows, also resends the message. Once the parent context is
// canceled, the function returns immediately with an error.
//
// Header format:
//   0B       1        2        3        4        5        6        7
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   | Flags  |                           PacketID                           |
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//
// RPT can be safely used by concurrent goroutines.
//
// All methods receive a context argument. If the context is canceled prior to
// completing work, ErrContextDone is returned. If the net.PacketConn
// connection is closed, running functions terminate with ErrClosed.
type RPT struct {
	conn net.PacketConn
	// Incrementing packet ID generator
	nextPktID uint56
	// Track senders waiting for ACKs
	ackTable ackTable
	// Channel for received messages, used between the background goroutine and receivers
	readEvents chan *readEventDesc
	// Closed when Close() starts to run
	closedChan chan struct{}
	// Closed when background goroutine finishes shutting down
	doneChan chan struct{}
	// Logger used by the background goroutine
	log log.Logger
	// Serialize write access to the conn object
	writeLock *util.ChannelLock
}

// New creates a new RPT connection by wrapping around a PacketConn.
//
// New also spawns a background receiving goroutine that continuously reads
// from conn and keeps track of ACKs and messages.
func New(conn net.PacketConn, logger log.Logger) *RPT {
	t := &RPT{
		conn:       conn,
		nextPktID:  uint56(generator.Int63n(maxUint56 + 1)),
		readEvents: make(chan *readEventDesc, maxReadEvents),
		closedChan: make(chan struct{}),
		doneChan:   make(chan struct{}),
		log:        logger.New("id", logext.RandId(4), "goroutine", "transport_bck"),
		writeLock:  util.NewChannelLock(),
	}
	t.goBackgroundReceiver()
	return t
}

// SendUnreliableMsgTo sends a message and returns without waiting for an ACK.
func (t *RPT) SendUnreliableMsgTo(ctx context.Context, b common.RawBytes, a net.Addr) error {
	id := t.nextPktID.Inc()
	buffer, err := t.putHeader(id, flagsNone, b)
	if err != nil {
		return err
	}
	defer bufpool.Put(buffer)
	return t.send(ctx, buffer.B, a)
}

// SendMsgTo sends a message and waits for an ACK. If no ACK is received for a
// set amount of time, the message is retransmitted. This process repeats while
// ctx is not canceled.
func (t *RPT) SendMsgTo(ctx context.Context, b common.RawBytes, a net.Addr) error {
	id := t.nextPktID.Inc()
	buffer, err := t.putHeader(id, flagNeedACK, b)
	if err != nil {
		return err
	}
	defer bufpool.Put(buffer)
	// Store the channel in the shared table s.t. the background receiver can
	// close it when it gets the ACK
	ackChannel := make(chan struct{})
	_, loaded := t.ackTable.LoadOrStore(id, ackChannel)
	if loaded {
		// Packet IDs should be unique, this points to a programming error
		panic(fmt.Sprintf("Duplicate session ID=%d", id))
	}

	defer t.ackTable.Delete(id)
	for {
		if err := t.send(ctx, buffer.B, a); err != nil {
			return err
		}
		select {
		case <-ackChannel:
			// Received ack and can return successfully
			return nil
		case <-ctx.Done():
			// Context was canceled or we are out of time, return with failure
			return infra.NewCtxDoneError()
		case <-time.After(rptRetryTimeout):
			// Did not get ACK and context is not canceled yet, so do nothing
			// and try to send again
		case <-t.closedChan:
			// Someone called Close, return immediately
			return common.NewBasicError(infra.StrClosedError, nil)
		}
	}
}

func (t *RPT) sendACK(id uint56, a net.Addr) error {
	buffer, err := t.putHeader(id, flagACK, nil)
	if err != nil {
		return err
	}
	defer bufpool.Put(buffer)
	ctx, cancelF := context.WithTimeout(context.Background(), rptACKTimeout)
	defer cancelF()
	return t.send(ctx, buffer.B, a)
}

// send sends b to a via the net.PacketConn object. send guarantees to return
// once ctx is canceled.
func (t *RPT) send(ctx context.Context, b common.RawBytes, a net.Addr) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return common.NewBasicError("Bad context, missing deadline", nil, "dst", a)
	}
	// NOTE(scrye): Even though WriteTo is concurrency-safe, we want to enforce
	// deadlines on each packet to prevent this function from blocking indefinitely.
	// Because a connection supports a single deadline, we serialize access via a lock.
	select {
	case <-t.writeLock.Lock():
		defer t.writeLock.Unlock()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := t.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	n, err := t.conn.WriteTo(b, a)
	if err != nil {
		return err
	}
	if err := t.conn.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	if n != len(b) {
		return common.NewBasicError("Unable to send complete message (message truncated)", nil,
			"sent_bytes", n, "msg_length", len(b))
	}
	return nil
}

// putHeader returns a new buffer containing the RPT header and b.
func (t *RPT) putHeader(id uint56, flags rptFlag, b common.RawBytes) (*bufpool.Buffer, error) {
	buffer := bufpool.Get()
	if rptHdrLen+len(b) > len(buffer.B) {
		bufpool.Put(buffer)
		return nil, common.NewBasicError("Unable to send, payload too long", nil,
			"pld_len", len(b), "max_allowed", len(buffer.B)-rptHdrLen)
	}
	buffer.B[0] = byte(flags)
	id.putUint56(buffer.B[1:])
	// Because we checked bounds above, this will never reallocate
	buffer.B = append(buffer.B[:rptHdrLen], b...)
	return buffer, nil
}

// RecvFrom returns the next non-ACK message.
func (t *RPT) RecvFrom(ctx context.Context) (common.RawBytes, net.Addr, error) {
	select {
	case event := <-t.readEvents:
		// Propagate message payload to caller
		b := event.buffer.CloneB()
		bufpool.Put(event.buffer)
		return b, event.address, nil
	case <-ctx.Done():
		// We timed out, return with failure
		return nil, nil, infra.NewCtxDoneError()
	case <-t.closedChan:
		// Some other goroutine closed the transport layer
		return nil, nil, common.NewBasicError(infra.StrClosedError, nil)
	}
}

// goBackgroundReceiver reads messages from the network and marks received ACKs
// in the ACK table.
func (t *RPT) goBackgroundReceiver() {
	go func() {
		defer liblog.LogPanicAndExit()
		t.log.Info("Started")
		defer t.log.Info("Stopped")
		defer close(t.doneChan)
		for {
			b := bufpool.Get()
			n, address, err := t.conn.ReadFrom(b.B)
			if err != nil {
				// FIXME(scrye): For now just log and continue on SCMP errors,
				// and destroy the background receiver on other errors.
				if opErr, ok := err.(*snet.OpError); ok && opErr.SCMP() != nil {
					t.log.Warn("Received SCMP message", "msg", opErr.SCMP())
					bufpool.Put(b)
					continue
				} else {
					// Do not log close events
					if err != io.EOF {
						t.log.Error("Read error, shutting down", "err", err)
					}
					bufpool.Put(b)
					return
				}
			}

			flags, id, payload, err := t.popHeader(b.B[:n])
			if err != nil {
				t.log.Error("Unable to remove RPT header", "err", err)
				bufpool.Put(b)
				continue
			}
			b.B = payload

			// If the received message is an ACK we do not propagate it up the
			// stack. Instead, we signal the waiting goroutine by closing its
			// channel.
			if flags.isSet(flagACK) {
				ackChannel, loaded := t.ackTable.Load(id)
				if !loaded {
					t.log.Warn("Received ACK, but no one is waiting for it", "id", id)
				} else {
					close(ackChannel)
				}
				bufpool.Put(b)
				continue
			}

			// The received message is for the upper layer.
			event := &readEventDesc{address: address, buffer: b}
			select {
			case t.readEvents <- event:
				// We reliably sent the message to the upper layer, send ACK
				// (if requested)
				if flags.isSet(flagNeedACK) {
					if err := t.sendACK(id, address); err != nil {
						t.log.Warn("Unable to send ACK", "err", err)
					}
				}
			default:
				t.log.Warn("Internal queue full, dropped message", "id", id, "flags", flags,
					"msg_len", n)
			}
		}
	}()
}

// popHeader returns a slice referring only to the payload of b.
func (t *RPT) popHeader(b common.RawBytes) (rptFlag, uint56, common.RawBytes, error) {
	if len(b) < rptHdrLen {
		return 0, 0, nil, common.NewBasicError("Packet shorter than min length", nil,
			"length", len(b), "min_length", rptHdrLen)
	}
	flags := rptFlag(b[0])
	id := getUint56(b[1:])
	return flags, id, b[rptHdrLen:], nil
}

// Close closes the net.PacketConn connection and shuts down the background
// goroutine. If Close blocks for too long while waiting for the goroutine to
// terminate, it returns ErrContextDone.
func (t *RPT) Close(ctx context.Context) error {
	close(t.closedChan)
	err := t.conn.Close()
	if err != nil {
		return common.NewBasicError("Unable to close conn", err)
	}
	// Wait for background goroutine to finish
	select {
	case <-ctx.Done():
		return infra.NewCtxDoneError()
	case <-t.doneChan:
		return nil
	}
}

type readEventDesc struct {
	buffer  *bufpool.Buffer
	address net.Addr
}
