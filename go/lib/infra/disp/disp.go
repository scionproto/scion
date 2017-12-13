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
// a reply message with the same key is received), Notify (send a message,
// block until an ACK is received from the remote Transport protocol),
// NotifyUnreliable (send a message, return immediately).
//
// A Dispatcher can be customized by implementing interface MessageAdapter. The
// inteface instructs the dispatcher how to convert a message to its raw
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
	"net"

	log "github.com/inconshreveable/log15"
	liblog "github.com/scionproto/scion/go/lib/log"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/messaging"
)

const (
	maxReadEvents = 1 << 8
)

type Dispatcher struct {
	// Used to send and receive messages
	transport messaging.Transport
	// Contains keys for messages awaiting replies
	waitTable *waitTable
	// Channel for messages read by the background receiver; drained by calls
	// to  RecvFrom
	readEvents chan *readEventDesc
	// Message Adapter, for converting messages to and from raw representations
	// and computing keys
	adapter MessageAdapter
	// Closed when background goroutine shuts down
	stoppedC chan struct{}
	// Closed when Close is called
	closeC chan struct{}
	log    log.Logger
}

// New creates a new dispatcher backed by transport t, and using adapter to
// convert generic Message objects to and from their raw representation.
//
// All methods guarantee to return immediately once their context is canceled.
//
// A Dispatcher can be safely used by concurrent goroutines.
func NewDispatcher(t messaging.Transport, adapter MessageAdapter, logger log.Logger) *Dispatcher {
	d := &Dispatcher{
		transport:  t,
		waitTable:  newWaitTable(adapter.MsgKey),
		adapter:    adapter,
		readEvents: make(chan *readEventDesc, maxReadEvents),
		stoppedC:   make(chan struct{}),
		closeC:     make(chan struct{}),
		log:        logger,
	}
	d.goBackgroundReceiver()
	return d
}

// Request sends msg to address, and returns a reply with the same key. This
// method always blocks while waiting for the response.
//
// No type validations are performed. Upper layer code should verify whether
// the message is the expected type.
func (d *Dispatcher) Request(ctx context.Context, msg Message, address net.Addr) (Message, error) {
	if err := d.waitTable.AddRequest(msg); err != nil {
		return nil, common.NewCError("Unable to register request", "err", err)
	}
	// Delete request entry when we exit this context
	defer d.waitTable.CancelRequest(msg)

	b, err := d.adapter.MsgToRaw(msg)
	if err != nil {
		return nil, common.NewCError("Unable to convert msg to raw", "err", err)
	}
	if err := d.transport.SendMsgTo(ctx, b, address); err != nil {
		return nil, common.NewCError("Unable to send message", "err", err)
	}

	reply, err := d.waitTable.WaitForReply(ctx, msg)
	if err != nil {
		return nil, common.NewCError("Waiting for reply failed", "err", err)
	}

	return reply, nil
}

// Notify sends msg to address, and returns once the send has been ACK'd by the
// remote end. This method always blocks while waiting for the ACK.
func (d *Dispatcher) Notify(ctx context.Context, msg Message, address net.Addr) error {
	b, err := d.adapter.MsgToRaw(msg)
	if err != nil {
		return common.NewCError("Unable to convert msg to raw", "err", err)
	}
	if err := d.transport.SendMsgTo(ctx, b, address); err != nil {
		return common.NewCError("Unable to send message", "err", err)
	}
	return nil
}

// NotifyUnreliable sends msg to address, and returns immediately.
func (d *Dispatcher) NotifyUnreliable(ctx context.Context, msg Message, address net.Addr) error {
	b, err := d.adapter.MsgToRaw(msg)
	if err != nil {
		return common.NewCError("Unable to convert msg to raw", "err", err)
	}
	if err := d.transport.SendUnreliableMsgTo(ctx, b, address); err != nil {
		return common.NewCError("Unable to send unreliable message", "err", err)
	}
	return nil
}

// RecvFrom returns the next non-reply message.
func (d *Dispatcher) RecvFrom(ctx context.Context) (Message, net.Addr, error) {
	select {
	case event := <-d.readEvents:
		return event.msg, event.address, nil
	case <-ctx.Done():
		// We timed out, return with failure
		return nil, nil, common.NewCError("Context canceled")
	case <-d.closeC:
		// Some other goroutine closed the dispatcher
		return nil, nil, common.NewCError("Closed")
	}
}

func (d *Dispatcher) goBackgroundReceiver() {
	go func() {
		defer liblog.LogPanicAndExit()
		d.log.Info("Dispatcher background goroutine starting")
		defer d.log.Info("Dispatcher background goroutine stopped")
		defer close(d.stoppedC)
		for {
			// On each iteration, check for termination signal
			select {
			case <-d.closeC:
				return
			default:
				d.recvNext()
			}
		}
	}()
}

func (d *Dispatcher) recvNext() {
	// Once the transport is closed, RecvFrom returns immediately.
	b, address, err := d.transport.RecvFrom(context.TODO())
	if err != nil {
		d.log.Warn("Unable to receive from transport layer", "err", err)
		return
	}

	msg, err := d.adapter.RawToMsg(b)
	if err != nil {
		d.log.Warn("Unable to convert raw content to message", "err", err)
		return
	}
	if d.adapter.MsgIsReply(msg) {
		if err := d.waitTable.Reply(msg); err != nil {
			d.log.Warn("Unable to signal reply", "err", err)
		}
		return
	}

	event := &readEventDesc{address: address, msg: msg}
	select {
	case d.readEvents <- event:
		// Do nothing
	default:
		d.log.Warn("Internal queue full, dropped message", "msg", msg)
	}
}

// Close shuts down the background goroutine and closes the transport.
func (d *Dispatcher) Close(ctx context.Context) error {
	close(d.closeC)
	err := d.transport.Close(ctx)
	if err != nil {
		return common.NewCError("Unable to close transport", "err", err)
	}
	// Wait for background goroutine to finish
	select {
	case <-ctx.Done():
		return common.NewCError("Context canceled")
	case <-d.stoppedC:
		return nil
	}
}

type readEventDesc struct {
	address net.Addr
	msg     Message
}
