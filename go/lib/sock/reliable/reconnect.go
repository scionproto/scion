// Copyright 2018 ETH Zurich
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

package reliable

import (
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// Dispatcher describes a local SCION Dispatcher process. It provides methods
// for connecting to said dispatcher.
//
// FIXME(scrye): Currently there is no support for externally canceling an
// already started RegisterTimeout.  This makes it impossible to implement a
// clean SetReadDeadline or SetWriteDeadline that unblocks any reading or write
// stuck in a reconnect (there are solutions, but they involve inelegant and
// flaky behaviors like leaking goroutines or implementing repeated
// RegisterTimeout retries with artificially lowered timeouts). If we implement
// cancelation support in the dispatcher client API, this gets much simpler.
type Dispatcher interface {
	// Register connects to a SCION Dispatcher process.
	Register(ia addr.IA, public, bind *AppAddr, svc addr.HostSVC) (DispatcherConn, uint16, error)

	// RegisterTimeout connects to a SCION Dispatcher process while respecting
	// timeout. To check for timeout errors, type assert the returned error to
	// *net.OpError and call method Timeout().
	//
	// FIXME(scrye): The negative = infinite semantics in the reliable socket
	// cause code clarity problems (especially where loops with decreasing
	// timeouts are involved, as eventually the timeout semantics go from "wait
	// a little" to "wait forever". The plan is to move away from these
	// semantics, which is why the interface no longer mentions negative values
	// having special meaning.  Also, the implementations here error out with a
	// timeout error immediately whenever a negative or 0 timeout is seen in
	// RegisterTimeout.
	RegisterTimeout(ia addr.IA, public, bind *AppAddr, svc addr.HostSVC,
		timeout time.Duration) (DispatcherConn, uint16, error)
}

// DispatcherConn is a net.PacketConn implementation describing connections to
// the local Dispatcher process. Implementations must guarantee that the Conn
// is safe for use from multiple goroutines.
type DispatcherConn interface {
	ReadFrom(buf []byte) (int, net.Addr, error)
	WriteTo(buf []byte, dst net.Addr) (int, error)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}

// NewDispatcher creates a new Dispatcher with no reconnection functionality.
// Every error is propagated back to the app immediately.
func NewDispatcher(dispatcherPath string) Dispatcher {
	return &dispatcher{dispatcherPath: dispatcherPath}
}

var _ Dispatcher = (*dispatcher)(nil)

// dispatcher is an implementation of interface Dispatcher with no reconnection
// functionality.
type dispatcher struct {
	dispatcherPath string
}

func (disp *dispatcher) Register(ia addr.IA, public, bind *AppAddr,
	svc addr.HostSVC) (DispatcherConn, uint16, error) {

	return Register(disp.dispatcherPath, ia, public, bind, svc)
}

func (disp *dispatcher) RegisterTimeout(ia addr.IA, public, bind *AppAddr, svc addr.HostSVC,
	timeout time.Duration) (DispatcherConn, uint16, error) {

	return RegisterTimeout(disp.dispatcherPath, ia, public, bind, svc, timeout)
}

var _ Dispatcher = (*reconnectingDispatcher)(nil)

// NewReconnectingDispatcher creates a new Dispatcher with transparent
// reconnection functionality. The process of reconnecting consists of multiple
// attempts to re-register with the local dispatcher socket.
//
// Reconnections are configured by three timers: maxTimeoutPerAttempt,
// minRetryInterval, and globalTimeout (specified on calls to RegisterTimeout).
//
// Timer maxTimeoutPerAttempt puts an upper limit on the timer for each
// attempt; the limit is enforced even if there is not timeout (i.e., as part
// of a Register attempt). To disable maxTimeoutPerAttempt, use a value
// smaller or equal to 0.
//
// Timer minRetryInterval puts a lower limit on the time between the start
// times of two successive attempts. For example, if minRetryInterval is 5, and
// the first attempt starts at T = 10, finishes at T = 12, the second attempt
// is made at T = 15. Two attempts cannot happen at once. For example, if
// minRetryInterval is 5, and the first attempts starts at T = 10, finishes at
// T = 18, the second attempt is made immediately afterwards at T = 18. To
// always retry immediately, use a value smaller or equal to 0.
//
// Timer globalTimeout puts an upper limit on the whole reconnection attempt
// process. Until the globalTimeout expires, multiple attempts can happen, each
// with their own timeout (depending on maxTimeoutPerAttempt and remaining
// available time). Note that globalTimeout refers to the argument of
// RegisterTimeout (as global timeout can vary due to external factors, such as
// read/write deadlines).
//
// The returned Dispatcher is safe for use from multiple goroutines.
func NewReconnectingDispatcher(dispatcher Dispatcher, numAttempts int,
	maxTimeoutPerAttempt, minRetryInterval time.Duration) Dispatcher {
	return &reconnectingDispatcher{
		dispatcher:           dispatcher,
		numAttempts:          numAttempts,
		maxTimeoutPerAttempt: maxTimeoutPerAttempt,
		minRetryInterval:     minRetryInterval,
	}
}

// reconnectingDispatcher is an implementation of interface Dispatcher with
// transparent reconnection functionality.
type reconnectingDispatcher struct {
	dispatcher           Dispatcher
	numAttempts          int
	maxTimeoutPerAttempt time.Duration
	minRetryInterval     time.Duration
}

func (disp *reconnectingDispatcher) Register(ia addr.IA, public, bind *AppAddr,
	svc addr.HostSVC) (DispatcherConn, uint16, error) {

	var (
		conn DispatcherConn
		port uint16
		err  error
	)
	for i := 0; i < disp.numAttempts; i++ {
		callStartTime := time.Now()
		if disp.maxTimeoutPerAttempt > 0 {
			conn, port, err = disp.dispatcher.RegisterTimeout(ia, public, bind, svc,
				disp.maxTimeoutPerAttempt)
		} else {
			conn, port, err = disp.dispatcher.Register(ia, public, bind, svc)
		}
		if disp.minRetryIntervalEnabled() {
			disp.waitMinRetryInterval(callStartTime)
		}
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, 0, err
	}
	return &reconnectingDispatcherConn{
		DispatcherConn: conn,
		dispatcher:     disp,
		ia:             ia,
		publicAddr:     copyAppAddrWithPort(public, port),
		bindAddr:       copyAppAddrWithPort(bind, port),
		svc:            svc,
		port:           port,
	}, port, nil
}

func (disp *reconnectingDispatcher) RegisterTimeout(ia addr.IA, public, bind *AppAddr,
	svc addr.HostSVC, timeout time.Duration) (DispatcherConn, uint16, error) {

	var (
		conn DispatcherConn
		port uint16
		err  error
	)
	globalDeadline := time.Now().Add(timeout)
	for i := 0; i < disp.numAttempts; i++ {
		callTimeout := disp.getNextTimeout(globalDeadline)
		callStartTime := time.Now()
		if callTimeout > 0 {
			conn, port, err = disp.dispatcher.RegisterTimeout(ia, public, bind, svc, callTimeout)
		} else {
			err = common.NewBasicError("Timed out", nil)
			break
		}
		if err != nil && disp.minRetryIntervalEnabled() {
			if disp.canWaitMinInterval(callStartTime, globalDeadline) {
				disp.waitMinRetryInterval(callStartTime)
			} else {
				// Not enough time to wait for next retry
				break
			}
		}
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, 0, err
	}
	return &reconnectingDispatcherConn{
		DispatcherConn: conn,
		dispatcher:     disp,
		ia:             ia,
		publicAddr:     copyAppAddrWithPort(public, port),
		bindAddr:       copyAppAddrWithPort(bind, port),
		svc:            svc,
		port:           port,
	}, port, nil
}

func (disp *reconnectingDispatcher) getNextTimeout(globalDeadline time.Time) time.Duration {

	timeout := globalDeadline.Sub(time.Now())
	if disp.maxTimeoutPerAttempt <= 0 {
		return timeout
	} else {
		return min(timeout, disp.maxTimeoutPerAttempt)
	}
}

func (disp *reconnectingDispatcher) canWaitMinInterval(lastRegisterStartTime,
	globalDeadline time.Time) bool {

	return lastRegisterStartTime.Add(disp.minRetryInterval).Before(globalDeadline)
}

func (disp *reconnectingDispatcher) waitMinRetryInterval(lastRegisterStartTime time.Time) {
	nextRegisterStartTime := lastRegisterStartTime.Add(disp.minRetryInterval)
	time.Sleep(nextRegisterStartTime.Sub(time.Now()))
}

func (disp *reconnectingDispatcher) minRetryIntervalEnabled() bool {
	return disp.minRetryInterval > 0
}

type reconnectingDispatcherConn struct {
	// lock is acquired during all operations on this object, for simplicity.
	// The socket layer below has a global lock anyway, so this shouldn't
	// significantly impact performance. If performance becomes a concern, more
	// intricate locking can be implemented.
	lock sync.Mutex
	DispatcherConn
	dispatcher Dispatcher
	ia         addr.IA
	publicAddr *AppAddr
	bindAddr   *AppAddr
	svc        addr.HostSVC
	// Port that was allocated by the dispatcher. This port will be explicitly
	// requested on reconnects, to prevent a socket's port from changing.
	port uint16
	// writeDeadline sets a deadline for writes. This includes reconnection
	// attempts made during writes.
	writeDeadline time.Time
	// readDeadline sets a deadline for writes. This includes reconnection
	// attempts made during reads.
	readDeadline time.Time
}

func (bc *reconnectingDispatcherConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	for {
		n, address, err := bc.DispatcherConn.ReadFrom(buf)
		if !errorNeedsReconnect(err) {
			return n, address, err
		}
		err = bc.reconnectToDispatcher(bc.readDeadline)
		if err != nil {
			return 0, nil, common.NewBasicError("Lost connection to dispatcher", nil,
				"last_error", err)
		}
	}
}

func (bc *reconnectingDispatcherConn) WriteTo(buf []byte, dst net.Addr) (int, error) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	for {
		n, err := bc.DispatcherConn.WriteTo(buf, dst)
		if !errorNeedsReconnect(err) {
			return n, err
		}
		err = bc.reconnectToDispatcher(bc.writeDeadline)
		if err != nil {
			return 0, common.NewBasicError("Lost connection to dispatcher", nil, "last_error", err)
		}
	}
}

func (bc *reconnectingDispatcherConn) SetWriteDeadline(t time.Time) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	err := bc.DispatcherConn.SetWriteDeadline(t)
	if err != nil {
		return err
	}
	bc.writeDeadline = t
	return nil
}

func (bc *reconnectingDispatcherConn) SetReadDeadline(t time.Time) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	err := bc.DispatcherConn.SetReadDeadline(t)
	if err != nil {
		return err
	}
	bc.readDeadline = t
	return nil
}

func (bc *reconnectingDispatcherConn) SetDeadline(t time.Time) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	err := bc.DispatcherConn.SetDeadline(t)
	if err != nil {
		return err
	}
	bc.writeDeadline = t
	bc.readDeadline = t
	return nil
}

func (bc *reconnectingDispatcherConn) reconnectToDispatcher(deadline time.Time) error {
	var conn DispatcherConn
	var err error
	if deadline.IsZero() {
		conn, _, err = bc.dispatcher.Register(bc.ia, bc.publicAddr, bc.bindAddr, bc.svc)
	} else {
		timeout := deadline.Sub(time.Now())
		conn, _, err = bc.dispatcher.RegisterTimeout(bc.ia, bc.publicAddr, bc.bindAddr, bc.svc,
			timeout)
	}
	if err != nil {
		return err
	}
	if err := conn.SetReadDeadline(bc.readDeadline); err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(bc.writeDeadline); err != nil {
		return err
	}
	bc.DispatcherConn = conn
	return nil
}

func errorNeedsReconnect(err error) bool {
	// On Linux, the following errors should prompt a reconnect:
	//   - An EOF, when a Read happens to a connection that was closed at the
	//   other end, and there is no outstanding outgoing data.
	//   - An EPIPE, when a Write happens to a connection that was closed at
	//   the other end.
	//   - An ECONNRESET, when a Read happens to a connection that was
	//   closed at the other end, and there is outstanding outgoing data. An
	//   ECONNRESET may be followed by EOF on repeated attempts.
	if err == io.EOF || isSysError(err, syscall.EPIPE) || isSysError(err, syscall.ECONNRESET) {
		return true
	}
	// All other errors can be immediately propagated back to the application.
	return false
}

func isSysError(err error, errno syscall.Errno) bool {
	nerr, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	serr, ok := nerr.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	return serr.Err == errno
}

func copyAppAddrWithPort(address *AppAddr, port uint16) *AppAddr {
	if address != nil {
		address = &AppAddr{Addr: address.Addr.Copy(), Port: port}
	}
	return address
}

func min(x, y time.Duration) time.Duration {
	if x < y {
		return x
	}
	return y
}
