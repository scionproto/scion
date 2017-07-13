// Package hello sends and receives keepalive messages across all active SIGS
// NOTE(all): Work in progress, do not recommend reviewing this code yet
package hello

import (
	"net"
	"strconv"
	"sync/atomic"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/global"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
)

type State uint64

const (
	RecvBufferSize       = 128
	StateDown      State = iota
	StateUp
)

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
	context *scion.Context
}

func NewModule() *Module {
	m := &Module{}
	m.queue = make(chan *Remote, 128)
	m.context = global.Context

	go m.echoServer()
	go m.run()
	return m
}

func (m *Module) Register(remote *Remote) error {
	ipAddr := net.ParseIP("0.0.0.0")
	if ipAddr == nil {
		return common.NewError("Unable to parse IP address", "address", remote.Address)
	}

	port, err := strconv.ParseUint(remote.Port, 10, 16)
	if err != nil {
		return common.NewError("Unable to parse port", "port", port)
	}

	log.Debug("Dialing for hello module")
	conn, err := m.context.DialSCION(remote.IA, addr.HostFromIP(ipAddr), uint16(port))
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

	// Start listening on control channel
	conn, err := m.context.ListenSCION(addr.HostFromIP(global.CtrlIP), global.CtrlPort)
	if err != nil {
		log.Error("Unable to listen on SCION conn", "err", err)
	}

	for {
		log.Warn("Key 2 - PreRead", "conn", conn)
		n, sa, err := conn.ReadFromSCION(b)
		log.Warn("Key 2 - PostRead", "conn", conn)

		if err != nil {
			log.Error("Unable to read from SCION socket", "err", err)
			continue
		}

		log.Debug("Received SCION Control message", "length", n, "sa", sa)
		msg := []byte("EchoReply")
		log.Warn("Key 3 - Sending hello reply", "sa", sa)
		n, err = conn.WriteTo(msg, sa)
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

			log.Warn("Key 1 - Sending hello", "remote", remote)
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

			log.Warn("Key 4 - PreRead", "remote", remote)
			err = m.receiveHello(remote)
			log.Warn("Key 4 - PostRead", "remote", remote)
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
			log.Debug("value of state before", "state", remote.state)
			if remote.swapState(StateDown, StateUp) {
				log.Debug("value of state after", "state", remote.state)
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
	log.Debug("Sending hello", "time", time.Now())
	_, err := remote.conn.Write([]byte("EchoRequest"))
	if err != nil {
		return common.NewError("Unable to write", "err", err)
	}
	return nil
}

func (m *Module) receiveHello(remote *Remote) error {
	// FIXME(scrye): add deadline for this operation
	log.Debug("Receiving hello", "time", time.Now())
	_, err := remote.conn.Read(remote.rcvBuffer)
	log.Debug("... after received hello")
	if err != nil {
		return common.NewError("Unable to read hello reply", "err", err)
	}
	log.Debug("Received hello reply", "message", remote.rcvBuffer)
	return nil
}
