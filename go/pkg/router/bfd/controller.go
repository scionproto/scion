// Copyright 2020 Anapaya Systems
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

package bfd

import (
	"sync"

	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Controller manages multiple BFD sessions, enforcing discriminator constraints and routing BFD
// messages to their proper Session.
//
// Routing is done based on local discriminator information. Remote discriminator information is not
// checked by the controller.
//
// The controller will discard BFD messages if it notices a session is slow to process them.
type Controller struct {
	// Sessions contains the sessions that the controller should manage. Both bootstrapped and
	// non-bootstrapped sessions are accepted.
	//
	// Passing in a slice of length 0 is allowed, although all BFD messages received by the
	// controller will be discarded in this case.
	//
	// Sessions must have unique local discriminators. If two sessions have the same discriminator,
	// running the controller will return an error.
	//
	// If a session is nil or has a local discriminator of 0, running the controller will return an
	// error.
	//
	// The controller will take ownership of the Sessions passed into it. When the controller is
	// shut down, it will also close all sessions. Callers must not clean up sessions after the
	// controller has been started.
	Sessions []*Session

	// sessions indexes sessions by discriminator, to provide fast routing of messages.
	sessions map[layers.BFDDiscriminator]*Session

	// ReceiveQueueSize is the size of the controller's receive messages queue. The default is 0,
	// but this is often not desirable as writing to the controller's message queue will block
	// until the controller is ready to read it.
	ReceiveQueueSize int

	// errorsLock protects the initialization of the errors channel.
	errorsLock sync.Mutex
	// errors is the channel on which the controller outputs fatal errors from the managed sessions.
	errors chan error

	// Logger to which the controller should send logging entries. If nil, logging is disabled.
	Logger log.Logger

	// messagesLock protects the initialization of the messages channel.
	messagesLock sync.Mutex
	// messages is the channel on which the controller receives BFD packets.
	messages chan *layers.BFD
}

// Run processes messages received by the controller.
//
// Run will return an error if the sessions contain inconsistent local discriminator information.
//
// If a session experiences a problem while running, Run will not return. For information on how to
// watch for such errors, see the Errors method.
//
// Run will continue to execute even if all sessions exited (and will run even though zero sessions
// are configured). To force Run to finish execution, close the controller's message channel.
func (c *Controller) Run() error {
	c.sessions = make(map[layers.BFDDiscriminator]*Session)

	for _, s := range c.Sessions {
		if s == nil {
			return serrors.New("session must not be nil")
		}
		if s.LocalDiscriminator == 0 {
			return serrors.New("local discriminator must not be 0")
		}
		_, ok := c.sessions[s.LocalDiscriminator]
		if ok {
			return serrors.New("duplicate local discriminator",
				"discriminator", s.LocalDiscriminator)
		}
		c.sessions[s.LocalDiscriminator] = s
	}

	c.initMessages()
	c.initErrors()

	var wg sync.WaitGroup
	wg.Add(len(c.sessions))

	for _, session := range c.sessions {
		session := session
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			if err := session.Run(); err != nil {
				c.errors <- serrors.WrapStr("session encountered fatal error", err,
					"local_discriminator", session.LocalDiscriminator)
				return
			}
			c.errors <- nil
		}()
	}

	for msg := range c.messages {
		localDiscriminator := msg.YourDiscriminator
		session, ok := c.sessions[localDiscriminator]
		if !ok {
			c.debug("discriminator not found, message discarded", "local_disc", localDiscriminator)
			continue
		}
		select {
		case session.Messages() <- msg:
		default:
			c.debug("session receive queue full, message discarded",
				"local_disc", localDiscriminator)
		}
	}

	for _, session := range c.sessions {
		close(session.Messages())
	}
	wg.Wait()
	return nil
}

// IsUp returns whether the Session identified by the local discriminator is up.
//
// If a session with the local discriminator does not exist, the function returns False.
func (c *Controller) IsUp(discriminator layers.BFDDiscriminator) bool {
	session, ok := c.sessions[discriminator]
	if !ok {
		return false
	}
	return session.IsUp()
}

// Messages returns a channel on which callers should write BFD packets received from the network.
// The Run method continuously processes packets received on this channel, and forwards them to the
// relevant Session based on the value of the Your Discriminator field. If the channel is closed,
// the Run method cleans up and shuts down.
func (c *Controller) Messages() chan<- *layers.BFD {
	c.initMessages()
	return c.messages
}

// initMessages creates and sets the message receive queue if it is not
// already created.
func (c *Controller) initMessages() {
	c.messagesLock.Lock()
	defer c.messagesLock.Unlock()
	if c.messages == nil {
		c.messages = make(chan *layers.BFD, c.ReceiveQueueSize)
	}
}

// Errors returns a channel on which callers can be informed of fatal errors in
// BFD Sessions. If an error is reported on the channel, the drainer can assume
// the corresponding Session has terminated.
//
// Sessions that shut down cleanly will send a nil error on this channel.
// Callers can thus track how many sessions have finished.
func (c *Controller) Errors() <-chan error {
	c.initErrors()
	return c.errors
}

// initErrors creates and sets the errors send queue if it is not
// already created.
func (c *Controller) initErrors() {
	c.errorsLock.Lock()
	defer c.errorsLock.Unlock()
	if c.errors == nil {
		c.errors = make(chan error, len(c.sessions))
	}
}

// debug logs a debug message if a logger is configured.
func (c *Controller) debug(msg string, ctx ...interface{}) {
	if c.Logger != nil {
		c.Logger.Debug(msg, ctx...)
	}
}
