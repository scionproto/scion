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

// Package hello sends and receives keepalive messages across all active SIGS
// NOTE(all): Work in progress, do not recommend reviewing this code yet
package hello

type State uint64

const (
	RecvBufferSize       = 128
	StateDown      State = iota
	StateUp
)

/*

type Remote struct {
	IA      *addr.ISD_AS
	Address string
	Port    string
	OnDown  func()
	OnUp    func()
	OnError func()

	failures uint64
	state    uint64
	conn     *scion.SCIONConn

	rcvBuffer []byte
}

func (r *Remote) swapState(old State, new State) bool {
	return atomic.CompareAndSwapUint64(&r.state, uint64(old), uint64(new))
}

type Module struct {
	queue   chan *Remote
	context *scion.SCIONNet
}

func NewModule() *Module {
	m := &Module{}
	m.queue = make(chan *Remote, 128)
	m.context = global.SCIONNet

	go m.echoServer()
	go m.run()
	return m
}

func (m *Module) Register(remote *Remote) error {
	ipAddr := net.ParseIP(remote.Address)
	if ipAddr == nil {
		return common.NewError("Unable to parse IP address", "address", remote.Address)
	}

	port, err := strconv.ParseUint(remote.Port, 10, 16)
	if err != nil {
		return common.NewError("Unable to parse port", "port", port)
	}

	log.Debug("Dialing for hello module")
	conn, err := m.context.DialSCION(remote.IA, addr.HostFromIP(global.CtrlIP), addr.HostFromIP(ipAddr), uint16(port))
	if err != nil {
		return common.NewError("Unable to dial SCION", "err", err)
	}
	remote.conn = conn
	remote.rcvBuffer = make([]byte, RecvBufferSize)

	m.queue <- remote
	log.Debug("Registered remote SIG for keepalives", "remote", remote)
	return nil
}

func (m *Module) Deregister(remote *Remote) error {
	// FIXME(scrye) delete remote SIGs from hello lists
	return common.NewError("Not implemented", "f", "Deregister")
}

func (m *Module) echoServer() {
	b := make([]byte, 1500)
	msg := []byte("BBBB    BBBB    BBBB    BBBB    ")
	// Start listening on control channel
	conn, err := m.context.ListenSCION(addr.HostFromIP(global.CtrlIP), global.CtrlPort)
	if err != nil {
		log.Error("Unable to listen on SCION conn", "err", err)
	}

	for {
		_, sa, err := conn.ReadFromSCION(b)
		if err != nil {
			log.Error("Unable to read from SCION socket", "err", err)
			continue
		}
		_, err = conn.WriteTo(msg, sa)
		if err != nil {
			log.Error("Unable to write to SCION destination", "msg", msg, "sa", sa)
		}
	}
}

func (m *Module) run() {
	for {
		remote := <-m.queue
		go func(queue chan<- *Remote, remote *Remote) {
			var err error

			err = m.sendHello(remote)
			if err != nil {
				remote.OnError()
				log.Warn("Unable to send Hello", "err", err)
				atomic.AddUint64(&remote.failures, 1)
				if remote.failures >= 3 && remote.swapState(StateUp, StateDown) {
					remote.OnDown()
				}
				return
			}

			// FIXME(scrye): add timeout for receiving
			err = m.receiveHello(remote)
			if err != nil {
				atomic.AddUint64(&remote.failures, 1)
				log.Warn("Unable to receive Hello", "err", err)
				remote.OnError()
				if remote.failures >= 3 && remote.swapState(StateUp, StateDown) {
					remote.OnDown()
				}
				return
			}

			// On successful receive reset error counter
			atomic.StoreUint64(&remote.failures, 0)
			if remote.swapState(StateDown, StateUp) {
				remote.OnUp()
			}
		}(m.queue, remote)

		// Reappend to request queue after 500 milliseconds from queue extraction
		go func(queue chan<- *Remote, remote *Remote) {
			<-time.After(500 * time.Millisecond)
			queue <- remote
		}(m.queue, remote)
	}
}

func (m *Module) sendHello(remote *Remote) error {
	_, err := remote.conn.WriteFoo([]byte("AAAA    AAAA    AAAA    AAAA    "))
	if err != nil {
		return common.NewError("Unable to write", "err", err)
	}
	return nil
}

func (m *Module) receiveHello(remote *Remote) error {
	// FIXME(scrye): add deadline for this operation
	_, err := remote.conn.Read(remote.rcvBuffer)
	if err != nil {
		return common.NewError("Unable to read hello reply", "err", err)
	}
	return nil
}

*/
