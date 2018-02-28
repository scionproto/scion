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

package main

import (
	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/snet"
)

const MaxReadBufSize = 2 << 16

// Dispatcher handles incoming SCION packets.
type Dispatcher struct {
	conn         *snet.Conn
	buf          common.RawBytes
	chainHandler *ChainHandler
	trcHandler   *TRCHandler
}

// NewDispatcher creates a new dispatcher listening to SCION traffic on the specified address.
func NewDispatcher(public, bind *snet.Addr) (*Dispatcher, error) {
	conn, err := snet.ListenSCIONWithBindSVC("udp4", public, bind, addr.SvcCS)
	if err != nil {
		return nil, err
	}
	d := &Dispatcher{conn: conn, buf: make(common.RawBytes, MaxReadBufSize)}
	d.chainHandler = NewChainHandler(d.conn)
	d.trcHandler = NewTRCHandler(d.conn)
	return d, nil
}

// run reads SCION packets from snet.
func (d *Dispatcher) run() {
	for {
		read, addr, err := d.conn.ReadFromSCION(d.buf)
		if err != nil {
			log.Error("Unable to read from network", "err", err)
			continue
		}
		buf := make(common.RawBytes, read)
		copy(buf, d.buf[:read])
		if err = d.dispatch(addr, buf); err != nil {
			log.Error("Unable to dispatch", "err", err)
		}

	}
}

// dispatch hands payload over tho the associated handlers.
func (d *Dispatcher) dispatch(addr *snet.Addr, buf common.RawBytes) error {
	signed, err := ctrl.NewSignedPldFromRaw(buf)
	if err != nil {
		return err
	}
	cpld, err := signed.Pld()
	if err != nil {
		return err
	}
	c, err := cpld.Union()
	if err != nil {
		return err
	}
	switch c.(type) {
	case *cert_mgmt.Pld:
		pld, err := c.(*cert_mgmt.Pld).Union()
		if err != nil {
			return err
		}
		switch pld.(type) {
		case *cert_mgmt.Chain:
			d.chainHandler.HandleRep(addr, pld.(*cert_mgmt.Chain))
		case *cert_mgmt.ChainReq:
			d.chainHandler.HandleReq(addr, pld.(*cert_mgmt.ChainReq))
		case *cert_mgmt.TRC:
			d.trcHandler.HandleRep(addr, pld.(*cert_mgmt.TRC))
		case *cert_mgmt.TRCReq:
			d.trcHandler.HandleReq(addr, pld.(*cert_mgmt.TRCReq))
		default:
			return common.NewBasicError("Handler for cert_mgmt.pld not implemented", nil,
				"protoID", pld.ProtoId())
		}
	default:
		return common.NewBasicError("Handler for cpld not implemented", nil, "protoID", c.ProtoId())
	}
	return nil
}

// SendPayload is used to send payloads to the specified address using snet.
func SendPayload(conn *snet.Conn, cpld *ctrl.Pld, addr *snet.Addr) error {
	buf, err := cpld.PackPld()
	if err != nil {
		return err
	}
	_, err = conn.WriteToSCION(buf, addr)
	return err
}
