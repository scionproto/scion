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
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
)

const (
	// defaultTransmissionInterval is the default interval between sent periodic BFD control
	// packets. This is used when the local session is Down, to avoid sending too much
	// network traffic.
	defaultTransmissionInterval = time.Second
	// defaultDetectionTimeout is used to arm the detection timer when the session is down.
	// This is not relevant from a BFD protocol perspective, because a timer expiring on a
	// session that is down does not change the state. However, having such a timer
	// simplifies the Go implementation's timer Stop/Reset code.
	defaultDetectionTimeout = time.Minute
)

var (
	// AlreadyRunning is the error returned by session run function when called for twice.
	AlreadyRunning = serrors.New("is running")
)

// Session describes a BFD Version 1 (RFC 5880) Session. Only Asynchronous mode is supported.
//
// Calling Run will start internal timers and cause the Session to start sending out BFD packets.
//
// Diagnostic codes are not supported. The field will always be set to 0, and diagnostic codes
// received from the remote will be ignored.
//
// The AdminDown state is not supported at the moment. Sessions will never send out packets with a
// State of 0 (AdminDown).
//
// The Control Plane Independent bit is cleared.
//
// Authentication is not supported. The Authentication Present bit of BFD packets is cleared.
//
// Session does not support the BFD Echo function. Therefore, the Required Min Echo RX field is
// always set to 0.
type Session struct {
	// Sender is used by the Session to send BFD messages to the other end of the point to point
	// link.
	//
	// Sender must not be nil.
	Sender Sender

	// LocalDiscriminator is the local discriminator for this BFD session, used
	// to uniquely identify it on the local system. It must be nonzero.
	LocalDiscriminator layers.BFDDiscriminator

	// RemoteDiscriminator is the remote discriminator for this BFD session, as chosen
	// by the remote system. If the Session has been bootstrapped via an external
	// mechanism, this should be non-zero. If it is zero, the Session will perform
	// bootstrapping.
	RemoteDiscriminator layers.BFDDiscriminator

	remoteDiscriminatorMtx sync.Mutex
	// remoteDiscriminator is the discriminator of the remote Session, as set
	// by the creator of the session or learned via bootstrapping. It is a
	// separate field from the exported remote discriminator to keep that
	// value read-only.
	remoteDiscriminator layers.BFDDiscriminator

	// DesiredMinTxInterval is the desired interval between BFD Control Packets
	// sent by the local system.
	//
	// The interval is relevant up to microsecond granularity; if the duration is not a whole
	// number of microseconds, the duration is rounded down to the next microsecond duration.
	//
	// The microsecond value obtained this way must be at least 1 and at most 2^32 - 1 microseconds.
	// Run will return an error if the interval falls outside this range.
	//
	// Note that this is only a recommendation, as the BFD state machine might choose to use
	// a different interval depending on network conditions (for example, an interval of 1 second if
	// the local session is down).
	DesiredMinTxInterval time.Duration

	// RequiredMinRxInterval is the minimum interval between BFD Control Packets supported by the
	// local system.
	//
	// The interval is relevant up to microsecond granularity; if the duration is not a whole number
	// of microseconds, the duration is rounded down to the next microsecond duration.
	//
	// The microsecond value obtained this way must be at least 1 and at most 2^32 - 1 microseconds.
	// Run will return an error if the interval falls outside this range.
	//
	// TEMPORARY API: The BFD RFC allows for this value to be 0, which means the system does not
	// want to receive any periodic BFD control packets (see section 6.8.1). This behavior is not
	// supported at the moment, and is subject to change.
	RequiredMinRxInterval time.Duration

	// DetectMult is the desired Detection Time multiplier for BFD Control packets on the local
	// system. The negotiated Control packet transmission interval, multiplied by this variable,
	// will be the Detection Time for this session (as seen by the remote system). This value
	// must be non-zero.
	DetectMult layers.BFDDetectMultiplier

	// ReceiveQueueSize is the size of the Session's receive messages queue. The default is 0,
	// but this is often not desirable as writing to the Session's message queue will block
	// until the session is ready to read it.
	ReceiveQueueSize int

	messagesOnce sync.Once
	// messages is the channel on which the session receives BFD packets.
	messages chan bfdMessage

	// localStateLock protects access to the local state.
	localStateLock sync.RWMutex
	// localState is the state of the local BFD session.
	localState state

	runMarkerLock sync.Mutex
	// runMarker is set to true the first time a Session runs. Subsequent calls use this value to
	// return an error.
	runMarker bool

	// desiredMinTXInterval is the desired transmission value included in sent packets. This
	// alternates, based on session state, between the default transmission interval and the
	// value explicitly configured in the public field.
	desiredMinTXInterval time.Duration

	// remoteState is the state of the remote BFD session, as reported by the last
	// seen periodic BFD control message.
	remoteState state

	// remoteMinRxInterval is the last value of Required Min RX interval received from the
	// remote system in a BFD Control packet.
	remoteMinRxInterval time.Duration

	// Metrics is used by the session to report information about internal operation.
	//
	// If a metric is not initialized, it is not reported.
	Metrics Metrics

	// testLogger is set if more logs should be generated, specifically, logs about
	// periodic events that would in production environment clog the logs. Use
	// this field only in tests.
	testLogger log.Logger
}

func (s *Session) String() string {
	return fmt.Sprintf("local_disc %v, remote_disc %v, sender %v",
		s.LocalDiscriminator, s.getRemoteDiscriminator(), s.Sender)
}

// Run initializes the Session's timers and state machine, and starts sending out BFD control
// packets on the point to point link.
//
// Run must only be called once.
func (s *Session) Run(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	if err := s.runOnceCheck(); err != nil {
		return err
	}
	if err := s.validateParameters(); err != nil {
		return err
	}
	if s.RemoteDiscriminator != 0 {
		s.setRemoteDiscriminator(s.RemoteDiscriminator)
	}
	s.initMessages()
	s.initMetrics()

	// detectionTimer tracks the period of time without receiving BFD packets after which the
	// session is determined to have failed.
	//
	// The initial duration is arbitrary, because the local session starts off in a Down state.
	// If the timer expires, the state is still Down. If we receive a packet from the network,
	// both the state and the timer will change.
	detectionTimer := time.NewTimer(defaultDetectionTimeout)
	s.setLocalState(stateDown)

	s.desiredMinTXInterval = defaultTransmissionInterval
	sendTimer := time.NewTimer(s.desiredMinTXInterval)

	pkt := &layers.BFD{}
MainLoop:
	for {
		select {
		case msg, ok := <-s.messages:
			if !ok {
				break MainLoop
			}

			// BFD packet is accepted. This means the detection timer can be reset.
			if !detectionTimer.Stop() {
				// Empty the channel to ensure a channel we don't get an extra read in the
				// main loop.
				<-detectionTimer.C
			}
			detectionTime := time.Duration(msg.DetectMultiplier) * max(
				s.RequiredMinRxInterval,
				bfdIntervalToDuration(msg.DesiredMinTxInterval))
			detectionTimer.Reset(detectionTime)

			if s.testLogger != nil {
				s.testLogger.Debug("heartbeat received", "desired_min_tx_interval",
					msg.DesiredMinTxInterval, "required_min_rx_interval", msg.RequiredMinRxInterval)
			}
			if s.Metrics.PacketsReceived != nil {
				s.Metrics.PacketsReceived.Add(1)
			}

			s.remoteState = state(msg.State)
			s.remoteMinRxInterval = bfdIntervalToDuration(msg.RequiredMinRxInterval)
			if s.getRemoteDiscriminator() == 0 {
				s.setRemoteDiscriminator(msg.MyDiscriminator)
				logger.Debug("Bootstrapped")
			}

			// If we transitioned out of the down state, we cancel the current send timer
			// (because it might send too late to keep the session up) and set up a new
			// send timer based on the remote's preferences.
			oldState := s.getLocalState()
			s.transition(ctx, event(s.remoteState))
			if oldState == stateDown && s.getLocalState() != stateDown {
				s.desiredMinTXInterval = s.DesiredMinTxInterval
				// Cancel any pending send to accelerate the timer.
				if !sendTimer.Stop() {
					<-sendTimer.C
				}
				sendTimer.Reset(s.computeNextSendInterval())
			}
		case <-sendTimer.C:
			// Send timer guaranteed to be expired, so we can reset.
			sendTimer.Reset(s.computeNextSendInterval())

			// These conversions are guaranteed to not return an error, because the input has been
			// sanitized.
			desiredMinTxInterval, _ := durationToBFDInterval(s.desiredMinTXInterval)
			requiredMinRxInterval, _ := durationToBFDInterval(s.RequiredMinRxInterval)

			*pkt = layers.BFD{
				Version:               1,
				State:                 layers.BFDState(s.getLocalState()),
				DetectMultiplier:      s.DetectMult,
				MyDiscriminator:       s.LocalDiscriminator,
				YourDiscriminator:     s.remoteDiscriminator,
				DesiredMinTxInterval:  desiredMinTxInterval,
				RequiredMinRxInterval: requiredMinRxInterval,
			}

			if err := s.Sender.Send(pkt); err != nil {
				logger.Debug("error sending message", "err", err)
				continue
			}
			if s.testLogger != nil {
				s.testLogger.Debug("heartbeat sent", "desired_min_tx_interval",
					pkt.DesiredMinTxInterval, "required_min_rx_interval", pkt.RequiredMinRxInterval)
			}
			if s.Metrics.PacketsSent != nil {
				s.Metrics.PacketsSent.Add(1)
			}
		case <-detectionTimer.C:
			// detection timer guaranteed to be expired, so we can reset. We reset s.t. if some
			// other branch wants to stop this timer, it can assume it hasn't been drained.
			detectionTimer.Reset(defaultDetectionTimeout)

			s.transition(ctx, eventTimer)
			s.setRemoteDiscriminator(0)
			if s.getLocalState() == stateDown {
				// Change the desired interval back to the default transmission interval, to
				// avoid flooding the network while the session is down.
				s.desiredMinTXInterval = defaultTransmissionInterval
			}
		}
	}
	return nil
}

func (s *Session) Close() error {
	s.initMessages()
	close(s.messages)
	return nil
}

func (s *Session) runOnceCheck() error {
	s.runMarkerLock.Lock()
	defer s.runMarkerLock.Unlock()
	if s.runMarker {
		return AlreadyRunning
	}
	s.runMarker = true
	return nil
}

func (s *Session) validateParameters() error {
	if s.DetectMult == 0 {
		return serrors.New("detection multiplier must be > 0")
	}
	desiredMinTxInterval, err := durationToBFDInterval(s.DesiredMinTxInterval)
	if err != nil {
		return serrors.Wrap("bad desired minimum transmission interval", err)
	}
	if desiredMinTxInterval == 0 {
		return serrors.New("desired minimum transmission interval must be > 0")
	}
	requiredMinRxInterval, err := durationToBFDInterval(s.RequiredMinRxInterval)
	if err != nil {
		return serrors.Wrap("bad required minimum receive interval", err)
	}
	if requiredMinRxInterval == 0 {
		return serrors.New("required minimum receive interval must be > 0")
	}
	if s.LocalDiscriminator == 0 {
		return serrors.New("local discriminator must be > 0")
	}
	if s.Sender == nil {
		return serrors.New("sender must not be nil")
	}
	return nil
}

func (s *Session) computeNextSendInterval() time.Duration {
	nextInterval := max(s.desiredMinTXInterval, s.remoteMinRxInterval)
	return computeInterval(nextInterval, uint(s.DetectMult), nil)
}

// IsUp returns whether the session is up. It is safe (and almost always the case) to call IsUp
// while Run is executed.
func (s *Session) IsUp() bool {
	up := s.getLocalState() == stateUp
	if s.testLogger != nil {
		s.testLogger.Debug("IsUp called", "up", up)
	}
	return up
}

// getLocalState is a concurrency-safe getter for local state.
func (s *Session) getLocalState() state {
	s.localStateLock.RLock()
	defer s.localStateLock.RUnlock()
	return s.localState
}

// setLocalState is a concurrency-safe setter for local state.
func (s *Session) setLocalState(st state) {
	s.localStateLock.Lock()
	defer s.localStateLock.Unlock()
	s.localState = st
}

func (s *Session) getRemoteDiscriminator() layers.BFDDiscriminator {
	s.remoteDiscriminatorMtx.Lock()
	defer s.remoteDiscriminatorMtx.Unlock()
	return s.remoteDiscriminator
}

func (s *Session) setRemoteDiscriminator(d layers.BFDDiscriminator) {
	s.remoteDiscriminatorMtx.Lock()
	defer s.remoteDiscriminatorMtx.Unlock()
	s.remoteDiscriminator = d
}

// ReceiveMessage validates a message and enqueues it for processing.
// Callers pass the message received from the network.
// The actual processing of the messages is asynchronous; the relevant message
// content is passed over a channel and the Run method continuously processes
// packets received on this channel. The caller can safely reuse packet buffer
// and the layers.BFD object.
//
// The session must be running when calling this function, i.e. Run must have
// been called.
func (s *Session) ReceiveMessage(msg *layers.BFD) {
	s.initMessages()

	discard, discardReason := shouldDiscard(msg)
	if discard {
		if discardReason != "" && s.testLogger != nil {
			s.testLogger.Debug(discardReason) // no session identifier to avoid data race
		}
		return
	}

	s.messages <- bfdMessage{
		State:                 msg.State,
		DetectMultiplier:      msg.DetectMultiplier,
		MyDiscriminator:       msg.MyDiscriminator,
		YourDiscriminator:     msg.YourDiscriminator,
		DesiredMinTxInterval:  msg.DesiredMinTxInterval,
		RequiredMinRxInterval: msg.RequiredMinRxInterval,
	}
}

// initMetrics initializes the metrics to a zero value.
func (s *Session) initMetrics() {
	if s.Metrics.Up != nil {
		s.Metrics.Up.Set(0)
	}
	if s.Metrics.PacketsReceived != nil {
		s.Metrics.PacketsReceived.Add(0)
	}
	if s.Metrics.PacketsSent != nil {
		s.Metrics.PacketsSent.Add(0)
	}
	if s.Metrics.StateChanges != nil {
		s.Metrics.StateChanges.Add(0)
	}
}

func (s *Session) initMessages() {
	s.messagesOnce.Do(func() {
		s.messages = make(chan bfdMessage, s.ReceiveQueueSize)
	})
}

func (s *Session) transition(ctx context.Context, e event) {
	// The only writer is the single Run method which also calls this, so we don't care
	// about making the state transition a transaction.

	logger := log.FromCtx(ctx)
	newState := transition(s.getLocalState(), e)
	if newState != s.localState {
		logger.Debug(fmt.Sprintf("Transitioned from state %v to state %v on event %v",
			s.localState, newState, e))
		s.setLocalState(newState)
		if s.Metrics.Up != nil {
			if newState == stateUp {
				s.Metrics.Up.Set(1)
			} else {
				s.Metrics.Up.Set(0)
			}
		}
		if s.Metrics.StateChanges != nil {
			s.Metrics.StateChanges.Add(1)
		}
	}
}

// Sender is used by a BFD session to send out BFD packets.
type Sender interface {
	Send(bfd *layers.BFD) error
}

// printPacket returns a concise representation of a BFD packet.
//
// Nil inputs are supported.
func printPacket(bfd *layers.BFD) string {
	if bfd == nil {
		return fmt.Sprintf("%v", bfd)
	}
	return fmt.Sprintf(
		"MyDisc: %v, YourDisc: %v, State: %v, DesMinTX: %v, ReqMinRX: %v",
		bfd.MyDiscriminator,
		bfd.YourDiscriminator,
		bfd.State,
		time.Duration(bfd.DesiredMinTxInterval)*time.Microsecond,
		time.Duration(bfd.RequiredMinRxInterval)*time.Microsecond,
	)
}

func max(x, y time.Duration) time.Duration {
	if x > y {
		return x
	}
	return y
}

// shouldDiscard returns true if the packet should be discarded, either (1) for a reason as defined
// in RFC 5880, Section 6.8.6 or (2) because the implementation lacks support for a certain feature.
//
// For case (2), the second return value will contain an explanation on what support is missing.
//
// For packets that are acceptable and are fully supported, the return values are false and the
// empty string.
func shouldDiscard(pkt *layers.BFD) (bool, string) {
	if pkt.Version != 1 {
		return true, ""
	}
	if !pkt.AuthPresent && pkt.Length() < 24 {
		return true, ""
	}
	if pkt.AuthPresent && pkt.Length() < 26 {
		// This also covers invalid combinations such as Auth flag set, but no Auth header / Auth
		// header with type none.
		return true, ""
	}
	if pkt.DetectMultiplier == 0 {
		return true, ""
	}
	if pkt.Multipoint {
		return true, ""
	}
	if pkt.MyDiscriminator == 0 {
		return true, ""
	}
	if pkt.YourDiscriminator == 0 {
		if !((pkt.State == layers.BFDStateAdminDown) || (pkt.State == layers.BFDStateDown)) {
			return true, ""
		}
	}
	if !pkt.AuthPresent {
		if pkt.AuthHeader != nil && pkt.AuthHeader.AuthType != layers.BFDAuthTypeNone {
			return true, ""
		}
	}

	// Authentication is not supported (see Anapaya/scion#3280). We currently discard
	// such packets.
	if pkt.AuthPresent {
		return true,
			"Received authenticated packet, but authentication is not supported. " +
				"Packet will be discarded."
	}

	// Poll/final sequences are not supported (see Anapaya/scion#3281).
	if pkt.Poll {
		return true, "Received Poll packet, but poll mechanism is not supported."
	}
	if pkt.Final {
		return true, "Received Final packet, but poll mechanism is not supported."
	}

	// Echo function is not supported. We discard such packets to ensure that the
	// session stays in a Down state. See Anapaya/scion#3285.
	if pkt.RequiredMinEchoRxInterval != 0 {
		return true, "Received request for Echo packets, but echo mechanism is not supported."
	}

	// Demand mode is not supported. We discard such packets to ensure that the
	// session stays in a Down state. See Anapaya/scion#3282.
	if pkt.Demand {
		return true, "Received Demand mode request, but Demand mode is not supported."
	}
	return false, ""
}

// durationToInterval converts a time.Duration value to a BFD uint32 microsecond count.
// If the duration is not a whole number of microseconds, it is truncated to a whole number.
// Negative durations or durations that overflow uint32 will return an error.
func durationToBFDInterval(d time.Duration) (layers.BFDTimeInterval, error) {
	if d < 0 {
		return 0, serrors.New("duration cannot be negative", "value", d)
	}

	i := uint64(d / time.Microsecond)
	if i > math.MaxUint32 {
		return 0, serrors.New("number of microseconds overflows uint32", "value", d)
	}
	return layers.BFDTimeInterval(i), nil
}

func bfdIntervalToDuration(x layers.BFDTimeInterval) time.Duration {
	return time.Duration(x) * time.Microsecond
}

// bfdMessage contains the relevant values to (asynchronously) process a BFD message
// received from the network. This is a subset of the fields of layers.BFD.
type bfdMessage struct {
	State                 layers.BFDState
	DetectMultiplier      layers.BFDDetectMultiplier
	MyDiscriminator       layers.BFDDiscriminator
	YourDiscriminator     layers.BFDDiscriminator
	DesiredMinTxInterval  layers.BFDTimeInterval
	RequiredMinRxInterval layers.BFDTimeInterval
}
