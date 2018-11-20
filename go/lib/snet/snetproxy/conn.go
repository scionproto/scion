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

package snetproxy

import (
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

var _ snet.Conn = (*ProxyConn)(nil)

type ProxyConn struct {
	// connMtx protects read/write access to the snetConn pointer. connMtx must
	// not be held when running methods on snetConn.
	connMtx  sync.Mutex
	snetConn snet.Conn

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

func NewProxyConn(conn snet.Conn, reconnecter Reconnecter) *ProxyConn {
	return &ProxyConn{
		snetConn:             conn,
		dispatcherState:      NewState(),
		reconnecter:          reconnecter,
		deadlineChangedEvent: make(chan struct{}, 1),
		fatalError:           make(chan error, 1),
		closeCh:              make(chan struct{}),
	}
}

func (conn *ProxyConn) Read(b []byte) (int, error) {
	op := &ReadOperation{}
	op.buffer = b
	err := conn.DoIO(op)
	return op.numBytes, err
}

func (conn *ProxyConn) ReadFrom(b []byte) (int, net.Addr, error) {
	op := &ReadFromOperation{}
	op.buffer = b
	err := conn.DoIO(op)
	return op.numBytes, op.address, err
}

func (conn *ProxyConn) ReadFromSCION(b []byte) (int, *snet.Addr, error) {
	op := &ReadFromSCIONOperation{}
	op.buffer = b
	err := conn.DoIO(op)
	return op.numBytes, op.address, err
}

func (conn *ProxyConn) Write(b []byte) (int, error) {
	op := &WriteOperation{}
	op.buffer = b
	err := conn.DoIO(op)
	return op.numBytes, err
}

func (conn *ProxyConn) WriteTo(b []byte, address net.Addr) (int, error) {
	op := &WriteToOperation{}
	op.buffer = b
	op.address = address.(*snet.Addr)
	err := conn.DoIO(op)
	return op.numBytes, err
}

func (conn *ProxyConn) WriteToSCION(b []byte, address *snet.Addr) (int, error) {
	op := &WriteToSCIONOperation{}
	op.buffer = b
	op.address = address
	err := conn.DoIO(op)
	return op.numBytes, err
}

func (conn *ProxyConn) DoIO(op IOOperation) error {
	conn.lockMutexForOpType(op)
	defer conn.unlockMutexForOpType(op)
	var err error
Loop:
	for {
		deadline := conn.getDeadlineForOpType(op)
		select {
		case <-conn.closeCh:
			return common.NewBasicError(ErrClosed, nil)
		case <-conn.dispatcherState.Up():
			err = op.Do(conn.getConn())
			if err != nil {
				if reliable.IsDispatcherError(err) &&
					!conn.isClosing() {
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
			return common.NewBasicError(ErrDispatcherDead, nil)
		}
	}
	return nil
}

func (conn *ProxyConn) lockMutexForOpType(op IOOperation) {
	if op.IsWrite() {
		conn.writeMtx.Lock()
	} else {
		conn.readMtx.Lock()
	}
}

func (conn *ProxyConn) unlockMutexForOpType(op IOOperation) {
	if op.IsWrite() {
		conn.writeMtx.Unlock()
	} else {
		conn.readMtx.Unlock()
	}
}

func (conn *ProxyConn) spawnAsyncReconnecterOnce() {
	conn.spawnReconnecterMtx.Lock()
	select {
	case <-conn.dispatcherState.Up():
		conn.dispatcherState.SetDown()
		go func() {
			defer log.LogPanicAndExit()
			conn.asyncReconnectWrapper()
		}()
	default:
	}
	conn.spawnReconnecterMtx.Unlock()
}

func (conn *ProxyConn) asyncReconnectWrapper() {
	newConn, err := conn.Reconnect()
	if err != nil {
		conn.fatalError <- err
		close(conn.fatalError)
		return
	}
	newConn.SetReadDeadline(conn.readDeadline)
	newConn.SetWriteDeadline(conn.writeDeadline)
	conn.setConn(newConn)
	conn.dispatcherState.SetUp()
}

// Reconnect is only used for testing purposes and should never be called.
func (conn *ProxyConn) Reconnect() (snet.Conn, error) {
	newConn, err := conn.reconnecter.Reconnect(0)
	if err != nil {
		return nil, err
	}
	if addressesEq(conn.getConn().LocalAddr(), newConn.LocalAddr()) == false {
		return nil, common.NewBasicError(ErrLocalAddressChanged, nil)
	}
	if addressesEq(conn.getConn().BindAddr(), newConn.BindAddr()) == false {
		return nil, common.NewBasicError(ErrBindAddressChanged, nil)
	}
	return newConn, nil
}

func (conn *ProxyConn) Close() error {
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

func (conn *ProxyConn) isClosing() bool {
	select {
	case <-conn.closeCh:
		return true
	default:
		return false
	}
}

func (conn *ProxyConn) LocalAddr() net.Addr {
	return conn.getConn().LocalAddr()
}

func (conn *ProxyConn) BindAddr() net.Addr {
	return conn.getConn().BindAddr()
}

func (conn *ProxyConn) SVC() addr.HostSVC {
	return conn.getConn().SVC()
}

func (conn *ProxyConn) RemoteAddr() net.Addr {
	return conn.getConn().RemoteAddr()
}

func (conn *ProxyConn) SetWriteDeadline(deadline time.Time) error {
	conn.writeDeadlineMtx.Lock()
	conn.getConn().SetWriteDeadline(deadline)
	conn.writeDeadline = deadline
	select {
	case conn.deadlineChangedEvent <- struct{}{}:
	default:
		// The channel contains an event already, so we are guaranteed the
		// channel reader sees the new deadline.
	}
	conn.writeDeadlineMtx.Unlock()
	return nil
}

func (conn *ProxyConn) SetReadDeadline(deadline time.Time) error {
	conn.readDeadlineMtx.Lock()
	conn.getConn().SetReadDeadline(deadline)
	conn.readDeadline = deadline
	select {
	case conn.deadlineChangedEvent <- struct{}{}:
	default:
		// The channel contains an event already, so we are guaranteed the
		// channel reader sees the new deadline.
	}
	conn.readDeadlineMtx.Unlock()
	return nil
}

func (conn *ProxyConn) SetDeadline(deadline time.Time) error {
	conn.SetWriteDeadline(deadline)
	conn.SetReadDeadline(deadline)
	return nil
}

func (conn *ProxyConn) getDeadlineForOpType(op IOOperation) time.Time {
	if op.IsWrite() {
		return conn.getWriteDeadline()
	}
	return conn.getReadDeadline()
}

func (conn *ProxyConn) getWriteDeadline() time.Time {
	conn.writeDeadlineMtx.Lock()
	deadline := conn.writeDeadline
	conn.writeDeadlineMtx.Unlock()
	return deadline
}

func (conn *ProxyConn) getReadDeadline() time.Time {
	conn.readDeadlineMtx.Lock()
	deadline := conn.readDeadline
	conn.readDeadlineMtx.Unlock()
	return deadline
}

func (conn *ProxyConn) getConn() snet.Conn {
	conn.connMtx.Lock()
	c := conn.snetConn
	conn.connMtx.Unlock()
	return c
}

func (conn *ProxyConn) setConn(newConn snet.Conn) {
	conn.connMtx.Lock()
	conn.snetConn = newConn
	conn.connMtx.Unlock()
}

func addressesEq(x, y net.Addr) bool {
	if x == nil || y == nil {
		return x == y
	}
	xSnet := x.(*snet.Addr)
	ySnet := y.(*snet.Addr)
	return xSnet.EqAddr(ySnet)
}

func returnOnDeadline(deadline time.Time) <-chan time.Time {
	var deadlineChannel <-chan time.Time
	if !deadline.IsZero() {
		deadlineChannel = time.After(deadline.Sub(time.Now()))
	}
	return deadlineChannel
}
