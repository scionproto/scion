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

package hello

import (
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/snet"
)

type Msg struct {
	Raddr   *snet.Addr
	Payload common.RawBytes
}

type Channels struct {
	Out chan Msg
	In  chan Msg
}

// Mux multiplexes/demultiplexes data traffic from multiple goroutines on a
// single SCION connection. The remote IA of received traffic is used to
// identify the goroutine to which to send.
type Mux struct {
	sync.Mutex
	m map[string]*Channels
	// The outgoing channel is shared
	out chan Msg
	// Connection for sends/receives
	conn *snet.Conn
}

func NewMux(conn *snet.Conn) *Mux {
	m := &Mux{
		m:    make(map[string]*Channels),
		out:  make(chan Msg, 10),
		conn: conn,
	}

	go runOutgoing()
	go runIngoing()
}

func (m *Mux) runOutgoing() {
	for {
		msg <- m.out
		n, err := conn.WriteToSCION(msg.Payload, msg.Raddr)
		if err != nil {
			log.Error("Unable to write")
		}
	}
}

func (m *Mux) runIngoing() {
	b := make([]byte, 1<<12)
	for {
		n, raddr, err := conn.ReadFromSCION(b)
		if err != nil {
			log.Error("Unable to read")
		}

		msg := Msg{raddr.Copy(), Payload: Copy(b[:n])}
		m[raddr.IA.String()].In <- msg
	}
}

func (m *Mux) AddRemote(ia *addr.ISD_AS) (*Channels, error) {
	m.Lock()
	defer m.Unlock()

	c := &Channels{
		Out: m.Out,
		In:  make(chan Msg, 10),
	}

	iaStr := ia.String()
	if _, ok := m.m[iaStr]; ok {
		return nil, common.NewError("duplicate entry", "remote", ia)
	}
	m.m[iaStr] = c
	return c, nil
}
