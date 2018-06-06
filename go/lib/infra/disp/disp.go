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

// Package disp implements a generic message dispatcher for request/reply
// protocols.
//
// Supported message exchanges are Request (send a request message, block until
// a reply message with the same key is received), Notify (send a reliable
// notification, i.e., one that is either sent via a lower-level reliable
// transport or waits for an ACK on an unreliable transport), and
// NotifyUnreliable (send a message, return immediately).
//
// A Dispatcher can be customized by implementing interface MessageAdapter. The
// interface instructs the dispatcher how to convert a message to its raw
// representation, how to parse a raw representation into a message, how to
// determine which messages are replies and how to extract keys (unique IDs)
// from messages.
//
// Protocols must clearly differentiate between request/notifications and
// replies. This is done by implementing MessageAdapter.IsReply. Replies are
// only used to finalize pending requests, and are not propagated back to the
// app via RecvFrom.
//
// Requests and Replies are paired via Keys. Once a request is sent out, its
// key is stored internally. If a reply is received for that same key, the
// request is marked as fulfilled and the waiting goroutine returns. If no
// request is outstanding for a reply key, it is ignored.
package disp

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

const (
	maxReadEvents = 1 << 8
)

type Dispatcher struct {
	// Used to send and receive messages
	transport infra.Transport
	// Contains keys for messages awaiting replies
	waitTable *waitTable
	// Channel for messages read by the background receiver; drained by calls
	// to  RecvFrom
	readEvents chan *readEventDesc
	// Message Adapter, for converting messages to and from raw representations
	// and computing keys
	adapter MessageAdapter
	// Closed when background goroutine shuts down
	stoppedChan chan struct{}
	// Logger used by the background goroutine
	log log.Logger

	// Protect against double close
	lock sync.Mutex
	// Closed when Close is called
	closedChan chan struct{}
}

// New creates a new dispatcher backed by transport t, and using adapter to
// convert generic Message objects to and from their raw representation.
//
// All methods guarantee to return immediately once their context expires.
// Calling the context's cancel function does not guarantee immediate return
// (lower levels might be blocked on an uninterruptible call).
//
// A Dispatcher can be safely used by concurrent goroutines.
func New(t infra.Transport, adapter MessageAdapter, logger log.Logger) *Dispatcher {
	d := &Dispatcher{
		transport:   t,
		waitTable:   newWaitTable(adapter.MsgKey),
		adapter:     adapter,
		readEvents:  make(chan *readEventDesc, maxReadEvents),
		stoppedChan: make(chan struct{}),
		closedChan:  make(chan struct{}),
		log:         logger.New("id", log.RandId(4), "goroutine", "dispatcher_bck"),
	}
	d.goBackgroundReceiver()
	return d
}

// Request sends msg to address, and returns a reply with the same key. This
// method always blocks while waiting for the response.
//
// No type validations are performed. Upper layer code should verify whether
// the message is the expected type.
func (d *Dispatcher) Request(ctx context.Context, msg proto.Cerealizable,
	address net.Addr) (proto.Cerealizable, error) {
	if err := d.waitTable.addRequest(msg); err != nil {
		return nil, common.NewBasicError(infra.StrInternalError, err, "op", "waitTable.AddRequest")
	}
	// Delete request entry when we exit this context
	defer d.waitTable.cancelRequest(msg)

	b, err := d.adapter.MsgToRaw(msg)
	if err != nil {
		return nil, common.NewBasicError(infra.StrAdapterError, err, "op", "adapter.MsgToRaw")
	}
	if err := d.transport.SendMsgTo(ctx, b, address); err != nil {
		return nil, common.NewBasicError(infra.StrTransportError, err, "op", "transport.SendMsgTo")
	}

	reply, err := d.waitTable.waitForReply(ctx, msg)
	if err != nil {
		return nil, common.NewBasicError(infra.StrInternalError, err, "op", "waitTable.WaitForReply")
	}
	return reply, nil
}

// Notify sends msg to address in a reliable way (i.e., either via a
// lower-level reliable transport or by waiting for an ACK on an unreliable
// transport).
func (d *Dispatcher) Notify(ctx context.Context, msg proto.Cerealizable, address net.Addr) error {
	b, err := d.adapter.MsgToRaw(msg)
	if err != nil {
		return common.NewBasicError(infra.StrAdapterError, err, "op", "MsgToRaw")
	}
	if err := d.transport.SendMsgTo(ctx, b, address); err != nil {
		return common.NewBasicError(infra.StrTransportError, err, "op", "SendMsgTo")
	}
	return nil
}

// NotifyUnreliable sends msg to address, and returns immediately.
func (d *Dispatcher) NotifyUnreliable(ctx context.Context, msg proto.Cerealizable,
	address net.Addr) error {
	b, err := d.adapter.MsgToRaw(msg)
	if err != nil {
		return common.NewBasicError(infra.StrAdapterError, err, "op", "MsgToRaw")
	}
	if err := d.transport.SendUnreliableMsgTo(ctx, b, address); err != nil {
		return common.NewBasicError(infra.StrTransportError, err, "op", "SendUnreliableMsgTo")
	}
	return nil
}

// RecvFrom returns the next non-reply message.
func (d *Dispatcher) RecvFrom(ctx context.Context) (proto.Cerealizable, net.Addr, error) {
	select {
	case event := <-d.readEvents:
		return event.msg, event.address, nil
	case <-ctx.Done():
		// We timed out, return with failure
		return nil, nil, infra.NewCtxDoneError()
	case <-d.closedChan:
		// Some other goroutine closed the dispatcher
		return nil, nil, common.NewBasicError(infra.StrClosedError, nil)
	}
}

func (d *Dispatcher) goBackgroundReceiver() {
	go func() {
		defer log.LogPanicAndExit()
		d.log.Info("Started")
		defer d.log.Info("Stopped")
		defer close(d.stoppedChan)
	Loop:
		for {
			// On each iteration, check for termination signal
			select {
			case <-d.closedChan:
				return
			default:
				if fatal := d.recvNext(); fatal {
					// fatal error
					break Loop
				}
			}
		}
	}()
}

// recvNext reads the next packet from the transport. On fatal errors, it
// returns true.
func (d *Dispatcher) recvNext() bool {
	// Once the transport is closed, RecvFrom returns immediately.
	b, address, err := d.transport.RecvFrom(context.Background())
	if err != nil {
		d.log.Warn("error", "err",
			common.NewBasicError(infra.StrTransportError, err, "op", "RecvFrom"))
		if err == io.EOF {
			return true
		}
		return false
	}

	msg, err := d.adapter.RawToMsg(b)
	if err != nil {
		d.log.Warn("error", "err",
			common.NewBasicError(infra.StrAdapterError, err, "op", "RawToMsg"))
		return false
	}

	found, err := d.waitTable.reply(msg)
	if err != nil {
		d.log.Warn("error", "err",
			common.NewBasicError(infra.StrInternalError, err, "op", "waitTable.Reply"))
		return false
	}
	if found {
		// If a waiting goroutine was found the message has already been forwarded
		return false
	}

	event := &readEventDesc{address: address, msg: msg}
	select {
	case d.readEvents <- event:
		// Do nothing
	default:
		d.log.Warn("Internal queue full, dropped message", "msg", msg)
	}
	return false
}

// Close shuts down the background goroutine and closes the transport.
func (d *Dispatcher) Close(ctx context.Context) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	select {
	case <-d.closedChan:
		// Some other goroutine already called Close()
		return nil
	default:
		close(d.closedChan)
	}
	err := d.transport.Close(ctx)
	if err != nil {
		return common.NewBasicError("Unable to close transport", err)
	}
	// Wait for background goroutine to finish
	select {
	case <-ctx.Done():
		return infra.NewCtxDoneError()
	case <-d.stoppedChan:
		return nil
	}
}

type readEventDesc struct {
	address net.Addr
	msg     proto.Cerealizable
}
