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

package reconnect

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/sock/reliable"
)

var _ net.PacketConn = (*PacketConn)(nil)

type PacketConn struct {
	// connMtx protects read/write access to connection information. connMtx must
	// not be held when running methods on the connection.
	connMtx  sync.Mutex
	dispConn net.PacketConn

	// readMtx is used to ensure only one reader enters the main I/O loop.
	readMtx sync.Mutex
	// writeMtx is used to ensure only one writer enters the main I/O loop.
	writeMtx sync.Mutex
	// spawnReconnecterMtx is used to ensure a single goroutine starts the
	// reconnecter. This must be acquired with either readMtx or writeMtx
	// taken.
	spawnReconnecterMtx sync.Mutex

	writeDeadlineMtx sync.Mutex
	writeDeadline    time.Time

	readDeadlineMtx sync.Mutex
	readDeadline    time.Time

	dispatcherState      *State
	reconnecter          Reconnecter
	deadlineChangedEvent chan struct{}
	// fatalError is written to by the async reconnecter on fatal errors, and then closed
	fatalError chan error
	// closeCh is closed when Close() is called, thus starting clean-up
	closeCh chan struct{}
	// closeMtx is used to guarantee that a single goroutine enters Close
	closeMtx sync.Mutex
}

func NewPacketConn(dispConn net.PacketConn, reconnecter Reconnecter) *PacketConn {
	return &PacketConn{
		dispConn:             dispConn,
		dispatcherState:      NewState(),
		reconnecter:          reconnecter,
		deadlineChangedEvent: make(chan struct{}, 1),
		fatalError:           make(chan error, 1),
		closeCh:              make(chan struct{}),
	}
}

func (conn *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	op := &ReadFromOperation{}
	op.buffer = b
	err := conn.DoIO(op)
	return op.numBytes, op.address, err
}

func (conn *PacketConn) WriteTo(b []byte, address net.Addr) (int, error) {
	op := &WriteToOperation{}
	op.buffer = b
	op.address = address
	err := conn.DoIO(op)
	return op.numBytes, err
}

func (conn *PacketConn) DoIO(op IOOperation) error {
	conn.lockMutexForOpType(op)
	defer conn.unlockMutexForOpType(op)
	var err error
Loop:
	for {
		deadline := conn.getDeadlineForOpType(op)
		select {
		case <-conn.closeCh:
			return ErrClosed
		case <-conn.dispatcherState.Up():
			err = op.Do(conn.getConn())
			if err != nil {
				if reliable.IsDispatcherError(err) && !conn.isClosing() {
					conn.spawnAsyncReconnecterOnce()
					continue
				} else {
					return err
				}
			}
			break Loop
		case err := <-conn.fatalError:
			return err
		case <-conn.deadlineChangedEvent:
		case <-returnOnDeadline(deadline):
			return ErrDispatcherDead
		}
	}
	return nil
}

func (conn *PacketConn) lockMutexForOpType(op IOOperation) {
	if op.IsWrite() {
		conn.writeMtx.Lock()
	} else {
		conn.readMtx.Lock()
	}
}

func (conn *PacketConn) unlockMutexForOpType(op IOOperation) {
	if op.IsWrite() {
		conn.writeMtx.Unlock()
	} else {
		conn.readMtx.Unlock()
	}
}

func (conn *PacketConn) spawnAsyncReconnecterOnce() {
	conn.spawnReconnecterMtx.Lock()
	select {
	case <-conn.dispatcherState.Up():
		conn.dispatcherState.SetDown()
		go func() {
			defer log.HandlePanic()
			conn.asyncReconnectWrapper()
		}()
	default:
	}
	conn.spawnReconnecterMtx.Unlock()
}

func (conn *PacketConn) asyncReconnectWrapper() {
	newConn, err := conn.Reconnect()
	if err != nil {
		conn.fatalError <- err
		close(conn.fatalError)
		return
	}
	if err := serrors.Join(
		newConn.SetReadDeadline(conn.getReadDeadline()),
		newConn.SetWriteDeadline(conn.getWriteDeadline()),
	); err != nil {
		conn.fatalError <- err
		close(conn.fatalError)
		return
	}
	conn.setConn(newConn)
	conn.dispatcherState.SetUp()
}

// Reconnect is only used internally and should never be called from outside
// the package.
func (conn *PacketConn) Reconnect() (net.PacketConn, error) {
	newConn, _, err := conn.reconnecter.Reconnect(context.Background())
	if err != nil {
		return nil, err
	}
	return newConn, nil
}

func (conn *PacketConn) Close() error {
	conn.closeMtx.Lock()
	defer conn.closeMtx.Unlock()
	if conn.isClosing() {
		panic("double close")
	}
	close(conn.closeCh)
	conn.reconnecter.Stop()
	// Once Stop() returns, it is guaranteed that snetConn is never recreated
	// by the reconnecter.
	err := conn.getConn().Close()
	return err
}

func (conn *PacketConn) isClosing() bool {
	select {
	case <-conn.closeCh:
		return true
	default:
		return false
	}
}

func (conn *PacketConn) LocalAddr() net.Addr {
	return conn.getConn().LocalAddr()
}

func (conn *PacketConn) SetWriteDeadline(deadline time.Time) error {
	conn.writeDeadlineMtx.Lock()
	err := conn.getConn().SetWriteDeadline(deadline)
	conn.writeDeadline = deadline
	select {
	case conn.deadlineChangedEvent <- struct{}{}:
	default:
		// The channel contains an event already, so we are guaranteed the
		// channel reader sees the new deadline.
	}
	conn.writeDeadlineMtx.Unlock()
	return err
}

func (conn *PacketConn) SetReadDeadline(deadline time.Time) error {
	conn.readDeadlineMtx.Lock()
	err := conn.getConn().SetReadDeadline(deadline)
	conn.readDeadline = deadline
	select {
	case conn.deadlineChangedEvent <- struct{}{}:
	default:
		// The channel contains an event already, so we are guaranteed the
		// channel reader sees the new deadline.
	}
	conn.readDeadlineMtx.Unlock()
	return err
}

func (conn *PacketConn) SetDeadline(deadline time.Time) error {
	return serrors.Join(
		conn.SetWriteDeadline(deadline),
		conn.SetReadDeadline(deadline),
	)
}

func (conn *PacketConn) getDeadlineForOpType(op IOOperation) time.Time {
	if op.IsWrite() {
		return conn.getWriteDeadline()
	}
	return conn.getReadDeadline()
}

func (conn *PacketConn) getWriteDeadline() time.Time {
	conn.writeDeadlineMtx.Lock()
	deadline := conn.writeDeadline
	conn.writeDeadlineMtx.Unlock()
	return deadline
}

func (conn *PacketConn) getReadDeadline() time.Time {
	conn.readDeadlineMtx.Lock()
	deadline := conn.readDeadline
	conn.readDeadlineMtx.Unlock()
	return deadline
}

func (conn *PacketConn) getConn() net.PacketConn {
	conn.connMtx.Lock()
	c := conn.dispConn
	conn.connMtx.Unlock()
	return c
}

func (conn *PacketConn) setConn(newConn net.PacketConn) {
	conn.connMtx.Lock()
	conn.dispConn = newConn
	conn.connMtx.Unlock()
}

func returnOnDeadline(deadline time.Time) <-chan time.Time {
	var deadlineChannel <-chan time.Time
	if !deadline.IsZero() {
		deadlineChannel = time.After(time.Until(deadline))
	}
	return deadlineChannel
}
