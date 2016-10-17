// Copyright 2016 ETH Zurich
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

package scmp

import (
	"bytes"
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type Payload struct {
	hdr     *Hdr
	Meta    *Meta
	Info    Info
	CmnHdr  util.RawBytes
	AddrHdr util.RawBytes
	PathHdr util.RawBytes
	ExtHdrs util.RawBytes
	L4Hdr   util.RawBytes
}

type Info interface{}

func PldFromRaw(b util.RawBytes, hdr *Hdr) (*Payload, *util.Error) {
	var err *util.Error
	p := &Payload{hdr: hdr}
	buf := bytes.NewBuffer(b)
	if p.Meta, err = MetaFromRaw(buf.Next(MetaLen)); err != nil {
		return nil, err
	}
	if err = p.parseInfo(buf.Next(int(p.Meta.InfoLen) * common.LineLen)); err != nil {
		return nil, err
	}
	p.CmnHdr = buf.Next(int(p.Meta.CmnHdrLen) * common.LineLen)
	p.AddrHdr = buf.Next(int(p.Meta.AddrHdrLen) * common.LineLen)
	p.PathHdr = buf.Next(int(p.Meta.PathHdrLen) * common.LineLen)
	p.ExtHdrs = buf.Next(int(p.Meta.ExtHdrsLen) * common.LineLen)
	p.L4Hdr = buf.Next(int(p.Meta.L4HdrLen) * common.LineLen)
	log.Debug("PldFromRaw", "pld", p)
	return p, nil
}

func (p *Payload) parseInfo(b util.RawBytes) *util.Error {
	var err *util.Error
	switch p.hdr.Class {
	case C_General:
		if p.hdr.Type == T_G_Unspecified {
			p.Info = string(b)
			return nil
		}
		p.Info, err = InfoEchoFromRaw(b)
		return err
	case C_Routing:
		if p.hdr.Type == T_R_OversizePkt {
			p.Info, err = InfoPktSizeFromRaw(b)
			return err
		}
	case C_CmnHdr:
		if p.hdr.Type == T_C_BadPktLen {
			p.Info, err = InfoPktSizeFromRaw(b)
			return err
		}
	case C_Path:
		switch p.hdr.Type {
		case T_P_PathRequired:
			return nil
		case T_P_RevokedIF:
			p.Info, err = InfoRevocationFromRaw(b)
			return err
		default:
			p.Info, err = InfoPathOffsetsFromRaw(b)
			return err
		}
		/*
			TODO(kormat): Ext and SIBRA errors not handled yet.
			case C_Ext:
				return InfoExtIdxFromRaw(b)
		*/
	}
	return nil
}

func (p *Payload) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "Hdr: %v\n", p.hdr)
	fmt.Fprintf(buf, "Meta: %v\n", p.Meta)
	if p.Info != nil {
		fmt.Fprintf(buf, "Info: %v\n", p.Info)
	}
	if p.CmnHdr != nil {
		fmt.Fprintf(buf, "CmnHdr: %v\n", p.CmnHdr)
	}
	if p.AddrHdr != nil {
		fmt.Fprintf(buf, "AddrHdr: %v\n", p.AddrHdr)
	}
	if p.PathHdr != nil {
		fmt.Fprintf(buf, "PathHdr: %v\n", p.PathHdr)
	}
	if p.ExtHdrs != nil {
		fmt.Fprintf(buf, "ExtHdrs: %v\n", p.ExtHdrs)
	}
	if p.L4Hdr != nil {
		fmt.Fprintf(buf, "L4Hdr: %v\n", p.L4Hdr)
	}
	return buf.String()
}
