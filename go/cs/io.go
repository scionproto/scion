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

	"github.com/netsec-ethz/scion/go/cs/msg"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl"
	"github.com/netsec-ethz/scion/go/lib/ctrl/cert_mgmt"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/proto"
)

// Dispatcher handles incoming SCION packets.
type Dispatcher struct {
	conn    *snet.Conn
	bufPool *msg.BufPool
}

// NewDispatcher creates a new dispatcher listening to SCION traffic on the specified address.
func NewDispatcher(addr *snet.Addr) (*Dispatcher, error) {
	conn, err := snet.ListenSCION("udp4", addr)
	if err != nil {
		return nil, err
	}
	return &Dispatcher{conn: conn, bufPool: msg.NewBufPool()}, nil
}

// run reads SCION packets from snet.
func (d *Dispatcher) run() {
	for {
		buf := d.bufPool.FetchBuf()
		read, addr, err := d.conn.ReadFromSCION(buf.Raw)
		if err != nil {
			log.Error("Unable to read from External Ingress", "err", err)
			d.bufPool.PutBuf(buf)
			continue
		}
		buf.Raw = buf.Raw[:read]
		buf.Addr = addr
		if err = d.dispatch(buf); err != nil {
			log.Error("Unable to dispatch", "err", err)
		}
		d.bufPool.PutBuf(buf)

	}
}

// dispatch hands payload over tho the associated handlers.
func (d *Dispatcher) dispatch(buf *msg.Buf) error {
	signed, err := ctrl.NewSignedPldFromRaw(buf.Raw)
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
	switch c.ProtoId() {
	case proto.CertMgmt_TypeID:
		pld, err := c.(*cert_mgmt.Pld).Union()
		if err != nil {
			return err
		}
		switch pld.ProtoId() {
		case proto.CertChainRep_TypeID:
			HandleChainRep(buf.Addr, pld.(*cert_mgmt.ChainRep), d.conn, d.bufPool)
		case proto.CertChainReq_TypeID:
			HandleChainReq(buf.Addr, pld.(*cert_mgmt.ChainReq), d.conn, d.bufPool)
		}
	default:
		return common.NewCError("Not implemented", "protoID", c.ProtoId())
	}
	return nil
}

// SendPayload is used to send payloads to the specified address using snet.
func SendPayload(addr *snet.Addr, cpld *ctrl.Pld, conn *snet.Conn, pool *msg.BufPool) error {
	buf := pool.FetchBuf()
	defer pool.PutBuf(buf)
	n, err := cpld.WritePld(buf.Raw)
	if err != nil {
		return err
	}
	_, err = conn.WriteToSCION(buf.Raw[:n], addr) // FIXME(roosd): handle incomplete writes
	return err
}
