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

// Router's implementation of the OPT hop-by-hop extension

package rpkt

import (
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/opt"
	/*"crypto/cipher"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/border/conf"*/
	"fmt"
	"hash"
	"github.com/netsec-ethz/scion/go/lib/drkey"
	"github.com/netsec-ethz/scion/go/lib/util"
)

// satisfies the interface rExtension in extns.go
var _ rExtension = (*rOPTExt)(nil)

// rOPTExt is the router's representation of the OPT extension.
type rOPTExt struct {
	rp  *RtrPkt
	raw common.RawBytes
	log.Logger
}

func rOPTExtFromRaw(rp *RtrPkt, start, end int) (*rOPTExt, *common.Error) {
	raw := rp.Raw[start:end]
	o := &rOPTExt{rp: rp, raw: raw}
	o.Logger = rp.Logger.New("ext", "SCIONOriginPathTrace")
	return o, nil
}

func (o *rOPTExt) Len() int {
	return len(o.raw)
}

func (o *rOPTExt) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (o *rOPTExt) Type() common.ExtnType {
	return common.ExtnOPTType
}

func (o *rOPTExt) RegisterHooks(h *hooks) *common.Error {
	// add hook to process field and update pvf
	o.rp.Logger.Error("B Nic")
	h.Process = append(h.Process, o.processOPT)
	return nil
}

// processOPT is a processing hook used to handle OPT payloads.
func (o *rOPTExt) processOPT() (HookResult, *common.Error) {
	// retrieve updated PVF via opt.Extn
	extn, err := o.GetOPTExtn()
	if err != nil {
		// fmt.Sprintf("SCIONOriginPathTrace - Failed to update PVF, %v: %v", err.Desc, err.String())
		return HookFinish, err
	}
	key, err := o.calcOPTRKey()
	if err != nil {
		return HookFinish, err
	}
	updatedPVF, err := extn.UpdatePVF(key)
	if err != nil {
		return HookFinish, err
	}
	o.rp.Logger.Error("B Eye")
	o.SetPVF(updatedPVF)
	return HookContinue, nil
}

// Datahash returns a slice of the underlying buffer
func (o *rOPTExt) Datahash() (common.RawBytes, *common.Error) {
	l, h, err := o.limitsDatahash()
	if err != nil {
		return nil, err
	}
	return o.raw[l:h], nil
}

// Set the Datahash directly in the underlying buffer
func (o *rOPTExt) SetDatahash(datahash common.RawBytes) *common.Error {
	hash, err := o.Datahash()
	if err != nil {
		return err
	}
	if len(hash) != len(datahash) {
		return common.NewError("Invalid datahash length", "expected", len(hash), "actual", len(datahash))
	}
	copy(hash, datahash)
	return nil
}

// SessionID returns a slice of the underlying buffer
func (o *rOPTExt) SessionID() (common.RawBytes, *common.Error) {
	l, h, err := o.limitsSessionID()
	if err != nil {
		return nil, err
	}
	return o.raw[l:h], nil
}

// Set the SessionID directly in the underlying buffer
func (o *rOPTExt) SetSessionID(sessionID common.RawBytes) *common.Error {
	session, err := o.SessionID()
	if err != nil {
		return err
	}
	if len(session) != len(sessionID) {
		return common.NewError("Invalid datahash length", "expected", len(session), "actual", len(sessionID))
	}
	copy(session, sessionID)
	return nil
}

// PVF returns a slice of the underlying buffer
func (o *rOPTExt) PVF() (common.RawBytes, *common.Error) {
	l, h, err := o.limitsPVF()
	if err != nil {
		return nil, err
	}
	return o.raw[l:h], nil
}

// Set the PVF directly in the underlying buffer
func (o *rOPTExt) SetPVF(pathVerificationField common.RawBytes) *common.Error {
	PVF, err := o.SessionID()
	if err != nil {
		return err
	}
	if len(PVF) != len(pathVerificationField) {
		return common.NewError("Invalid datahash length", "expected", len(PVF), "actual", len(pathVerificationField))
	}
	copy(PVF, pathVerificationField)
	return nil
}

// calcDRKey calculates the DRKey for this packet.
func (o *rOPTExt) calcOPTRKey() (common.RawBytes, *common.Error) {
	// stuff in with src ISD|src AS, compute CBCMac over it with key DRKeyAESBlock: K_x = cbcmac(DRKeyAESBlock, in)
	in := make(common.RawBytes, 16)
	common.Order.PutUint32(in, uint32(o.rp.srcIA.I))
	common.Order.PutUint32(in[4:], uint32(o.rp.srcIA.A))

	mac := o.rp.Ctx.Conf.DRKeyPool.Get().(hash.Hash)
	key, err := util.Mac(mac, in)
	o.rp.Ctx.Conf.DRKeyPool.Put(mac)

	// blockFstOrder is K_{SV_{AS_i}}
	/*blockFstOrder, e := o.getDRKeyBlock(util.CBCMac(conf.C.DRKeyAESBlock, in))*/
	if err != nil {
		return nil, err
	}

	mac, err = util.InitMac(key)
	if err != nil {
		return nil, err
	}

	inputType, err := drkey.InputTypeFromHostTypes(o.rp.dstHost.Type(), 0)

	in = make(common.RawBytes, 48)
	in[0] = uint8(inputType)
	in[1] = uint8(len("OPT"))
	copy(in[2:5], []byte("OPT"))
	copy(in[16:32], o.rp.srcHost.Pack())
	copy(in[32:48], o.rp.dstHost.Pack())
	// keyOpt is K^OPT_{AS_i -> S:H_S, D:H_D}
	//keyOpt, e := util.CBCMac(blockFstOrder, in)
	return util.Mac(mac, in)
}

// GetExtn returns the opt.Extn representation,
// which does not have direct access to the underlying buffer.
func (o *rOPTExt) GetExtn() (common.Extension, *common.Error) {
	extn, err := opt.NewExtn()
	if err != nil {
		return nil, err
	}
	hash, err := o.Datahash()
	if err != nil {
		return nil, err
	}
	extn.SetDatahash(hash)
	session, err := o.SessionID()
	if err != nil {
		return nil, err
	}
	extn.SetSessionID(session)
	PVF, err := o.PVF()
	if err != nil {
		return nil, err
	}
	extn.SetPVF(PVF)
	return extn, nil
}

func (o *rOPTExt) GetOPTExtn() (opt.Extn, *common.Error) {
	extn, _ := opt.NewExtn()
	// WIP
	return *extn, nil
}

func (o *rOPTExt) String() string {
	// retrieve string representation via opt.Extn
	extn, err := o.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCIONOriginPathTrace - %v: %v", err.Desc, err.String())
	}
	return extn.String()
}

// limitsDatahash returns the limits of the Datahas in the raw buffer
func (o *rOPTExt) limitsDatahash() (int, int, *common.Error) {
	size := opt.DatahashLength
	return 0, 0 + size, nil
}

// limitsSessionID returns the limits of the Datahas in the raw buffer
func (o *rOPTExt) limitsSessionID() (int, int, *common.Error) {
	size := opt.SessionIDLength
	_, l, _ := o.limitsDatahash()
	return l, l + size, nil
}

// limitsDatahash returns the limits of the Datahas in the raw buffer
func (o *rOPTExt) limitsPVF() (int, int, *common.Error) {
	size := opt.PVFLength
	_, l, _ := o.limitsSessionID()
	return l, l + size, nil
}
