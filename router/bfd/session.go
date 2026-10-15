// Copyright 2020 Anapaya Systems
// Copyright 2025 SCION Association
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
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/router/control"
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
	// initialRTTMeasurementInterval is the initial interval between Poll Sequences used to
	// estimate the RTT. The effective measurement interval is scaled between
	// 2*desiredMinTXInterval and maxRTTMeasurementInterval. The Poll bit is set on the next
	// periodic packet after the interval elapsed.
	initialRTTMeasurementInterval = 500 * time.Millisecond
	// maxRTTMeasurementInterval is the maximum interval between attempting Poll sequences for RTT
	// estimation. If the remote session does not respond to Poll packets, the measurement will
	// settle to this interval.
	maxRTTMeasurementInterval = 10 * time.Second
	// defaultRTTEWMAWeight is the default value for RTTEWMAWeight.
	defaultRTTEWMAWeight = 0.5
)

// ErrAlreadyRunning is the error returned by session run function when called repeatedly.
var ErrAlreadyRunning = errors.New("is running")

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
//
// Poll Sequences are supported. If EnableRTTEstimate is true periodic Poll Sequences are used to
// estimate the RTT between border routers. As required by RFC 5880 Section 6.5, Poll Sequences are
// initiated by setting the Poll bit on a scheduled packet; no additional packets are sent. Each
// Poll Sequence consists of a single Poll packet. If no Final is received before the next periodic
// transmission, the sequence is abandoned without an RTT sample. Consequently, only RTTs shorter
// than 75% (BFD allows 25% jitter) of the transmission interval can be measured. The Poll bit is
// set on at most one consecutive packet to maintain compatibility with old routers that discard all
// Poll packets without updating the session state.
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

	// EnableRTTEstimate enables RTT estimation by Poll Sequences.
	EnableRTTEstimate bool

	// Weight for new samples in exponentially weighted moving average that estimates the session
	// RTT. This weight is based one a second measurement interval and will be adjusted if the
	// actual measurement interval differs. Must be in [0, 1]. If 0, the default value of 0.5 is
	// used.
	RTTEWMAWeight float64

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

	// pollScheduled is true if the next periodic control packet should start a Poll Sequence.
	pollScheduled bool
	// pollInFlight is true if a poll sequence is in progress.
	pollInFlight bool
	// pollSendTime is the time at which a packet with the Poll bit was sent.
	pollSendTime time.Time
	// lastSuccessfulPoll is the last time the RTT was updated successfully.
	lastSuccessfulPoll time.Time

	// rttLock protects access to rttEstimate and rttValid
	rttLock sync.RWMutex
	// rttEstimate is the current smoothed RTT estimate
	rttEstimate time.Duration
	// rttValid indicated whether rttEstimate is valid
	rttValid bool

	// Metrics is used by the session to report information about internal operation.
	//
	// If a metric is not initialized, it is not reported.
	Metrics Metrics

	// testLogger is set if more logs should be generated, specifically, logs about
	// periodic events that would in production environment clog the logs. Use
	// this field only in tests.
	testLogger log.Logger
}

// NewSession returns a new BFD session, configured as specified and updating the
// given metrics. BFD packets are transmitted via the given Sender. Up to 10 incoming BFD packets
// per session can be queued waiting for processing; excess traffic will be blocked.
// A random discriminator is generated automatically. This can be used by the recipient to route
// packets to the correct session.
//
// TODO(jiceatscion): blocking incoming traffic (*all of it*) when the BFD queue is full is
// probably the wrong thing to do, but this is what we have been doing so far.
func NewSession(s Sender, cfg control.BFD, metrics Metrics) (*Session, error) {
	// Generate random discriminator. It can't be zero.
	discInt, err := rand.Int(rand.Reader, big.NewInt(0xfffffffe))
	if err != nil {
		return nil, err
	}
	disc := layers.BFDDiscriminator(uint32(discInt.Uint64()) + 1)
	return &Session{
		Sender:                s,
		DetectMult:            layers.BFDDetectMultiplier(cfg.DetectMult),
		DesiredMinTxInterval:  cfg.DesiredMinTxInterval,
		RequiredMinRxInterval: cfg.RequiredMinRxInterval,
		LocalDiscriminator:    disc,
		ReceiveQueueSize:      10,
		EnableRTTEstimate:     !cfg.DisableRTT,
		RTTEWMAWeight:         cfg.RTTEWMAWeight,
		Metrics:               metrics,
	}, nil
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

	var pollTimerC <-chan time.Time
	var pollTimer *time.Timer
	rttInterval := initialRTTMeasurementInterval
	if s.EnableRTTEstimate {
		pollTimer = time.NewTimer(rttInterval)
		pollTimerC = pollTimer.C
	}

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

			// RFC 5880 Section 6.8.7: Upon receiving a packet with the Poll bit set, must transmit
			// a packet with Poll clear and Final set as soon as practicable without respect to the
			// transmission timer.
			if msg.Poll {
				s.sendFinal(pkt, logger)
			} else if msg.Final && s.pollInFlight {
				s.pollInFlight = false
				s.updateRTT(msg.ReceivedAt.Sub(s.pollSendTime))
				rttInterval = max((3*rttInterval)/4, 2*s.desiredMinTXInterval)
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
			if s.pollInFlight {
				// No final received within one transmission interval, either because the RTT is
				// higher than the interval or the poll was dropped.
				s.pollInFlight = false
				rttInterval = min(2*rttInterval, maxRTTMeasurementInterval)
			} else if s.pollScheduled && s.getLocalState() == stateUp {
				s.pollScheduled = false
				s.pollInFlight = true
				s.pollSendTime = time.Now()
				pkt.Poll = true
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

		case <-pollTimerC:
			pollTimer.Reset(rttInterval)
			if s.getLocalState() == stateUp && !s.pollInFlight {
				s.pollScheduled = true
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
				s.pollScheduled = false
				s.pollInFlight = false
				s.rttLock.Lock()
				s.rttEstimate = 0
				s.rttValid = false
				s.rttLock.Unlock()
				if s.Metrics.RTT != nil {
					s.Metrics.RTT.Set(0)
				}
				rttInterval = initialRTTMeasurementInterval
			}
		}
	}
	return nil
}

func (s *Session) sendFinal(pkt *layers.BFD, logger log.Logger) {
	desiredMinTxInterval, _ := durationToBFDInterval(s.desiredMinTXInterval)
	requiredMinRxInterval, _ := durationToBFDInterval(s.RequiredMinRxInterval)
	*pkt = layers.BFD{
		Version:               1,
		Final:                 true,
		State:                 layers.BFDState(s.getLocalState()),
		DetectMultiplier:      s.DetectMult,
		MyDiscriminator:       s.LocalDiscriminator,
		YourDiscriminator:     s.remoteDiscriminator,
		DesiredMinTxInterval:  desiredMinTxInterval,
		RequiredMinRxInterval: requiredMinRxInterval,
	}
	if err := s.Sender.Send(pkt); err != nil {
		logger.Debug("error sending final", "err", err)
		return
	}
	if s.testLogger != nil {
		s.testLogger.Debug("final sent", "remoteDiscriminator", pkt.YourDiscriminator)
	}
	if s.Metrics.PacketsSent != nil {
		s.Metrics.PacketsSent.Add(1)
	}
}

func (s *Session) updateRTT(sample time.Duration) {
	w := s.RTTEWMAWeight
	if w <= 0 {
		w = defaultRTTEWMAWeight
	}
	now := time.Now()
	s.rttLock.Lock()
	defer s.rttLock.Unlock()
	if !s.rttValid {
		s.rttEstimate = sample
		s.rttValid = true
	} else {
		delta := now.Sub(s.lastSuccessfulPoll)
		alpha := 1.0 - math.Pow(1.0-w, delta.Seconds())
		s.rttEstimate = time.Duration(alpha*float64(sample) + (1-alpha)*float64(s.rttEstimate))
	}
	s.lastSuccessfulPoll = now
	if s.testLogger != nil {
		s.testLogger.Debug("RTT updated", "sample", sample, "estimate", s.rttEstimate)
	}
	if s.Metrics.RTT != nil {
		s.Metrics.RTT.Set(s.rttEstimate.Seconds())
	}
}

// RTT return a smoothed estimate for the RTT and a flag whether the estimate is
// valid. There is no valid estimate while the session is down or if the remote
// side does not support BFD Poll sequences.
func (s *Session) RTT() (time.Duration, bool) {
	s.rttLock.RLock()
	defer s.rttLock.RUnlock()
	return s.rttEstimate, s.rttValid
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
		return ErrAlreadyRunning
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
	if s.RTTEWMAWeight < 0.0 || s.RTTEWMAWeight > 1.0 {
		return serrors.New("RTTEWMAWeight must be in [0, 1]")
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

	// The packet will be returning to the pool. We do not keep a reference to any part of it.
	s.messages <- bfdMessage{
		ReceivedAt:            time.Now(),
		Poll:                  msg.Poll,
		Final:                 msg.Final,
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
	if pkt.YourDiscriminator == 0 &&
		pkt.State != layers.BFDStateAdminDown &&
		pkt.State != layers.BFDStateDown {
		return true, ""
	}
	if !pkt.AuthPresent &&
		pkt.AuthHeader != nil &&
		pkt.AuthHeader.AuthType != layers.BFDAuthTypeNone {
		return true, ""
	}

	// Authentication is not supported (see Anapaya/scion#3280). We currently discard
	// such packets.
	if pkt.AuthPresent {
		return true,
			"Received authenticated packet, but authentication is not supported. " +
				"Packet will be discarded."
	}

	// RFC 5880 Section 6.5: Poll and Final must not both be set.
	if pkt.Poll && pkt.Final {
		return true, "Received invalid packet with both Poll and Final bits set."
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
	ReceivedAt            time.Time
	State                 layers.BFDState
	Poll                  bool
	Final                 bool
	DetectMultiplier      layers.BFDDetectMultiplier
	MyDiscriminator       layers.BFDDiscriminator
	YourDiscriminator     layers.BFDDiscriminator
	DesiredMinTxInterval  layers.BFDTimeInterval
	RequiredMinRxInterval layers.BFDTimeInterval
}
