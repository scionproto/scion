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

	"fmt"
	"hash"

	"github.com/netsec-ethz/scion/go/lib/drkey"
	"github.com/netsec-ethz/scion/go/lib/spath"
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
	o.rp.Logger.Info("Registered OPT hook")
	h.Process = append(h.Process, o.processOPT)
	return nil
}

// processOPT is a processing hook used to handle OPT payloads.
func (o *rOPTExt) processOPT() (HookResult, *common.Error) {
	// Check if we need to process the extension
	hOff := o.rp.CmnHdr.HopFOffBytes()
	currHopF, err := spath.HopFFromRaw(o.rp.Raw[hOff:])
	if err != nil {
		return HookError, err
	}
	o.rp.Logger.Info(fmt.Sprint(currHopF.Ingress))

	key, err := o.calcOPTDRKey()
	if err != nil {
		return HookError, err
	}
	extn, err := opt.NewExtn()
	meta, _ := o.Meta()
	extn.SetMeta(meta)
	datahash, _ := o.Datahash()
	o.rp.Logger.Info(fmt.Sprintf("Extension with datahash (%d): %v", len(datahash.String()), datahash.String()))
	PVF, _ := o.PVF()
	o.rp.Logger.Info(fmt.Sprintf("Received PVF (%d): %v", len(PVF.String()), PVF.String()))
	extn.SetDatahash(datahash)
	extn.SetPVF(PVF)
	sessionID, _ := o.SessionID()
	extn.SetSessionID(sessionID)
	updatedPVF, err := extn.UpdatePVF(key)
	o.rp.Logger.Info(fmt.Sprintf("updatedPVF (%d): from %v to %v with key %v",
		len(updatedPVF.String()), PVF.String(), updatedPVF.String(), key.String()))
	if err != nil {
		return HookError, err
	}
	o.SetPVF(updatedPVF)
	OVs, _ := o.OVs()
	err = extn.SetOVs(OVs)
	o.rp.Logger.Info(fmt.Sprintf("OVs count %v, First OV (%v): %x, meta: %v", len(extn.OVs), len(extn.OVs[0]), extn.OVs[0], meta))
	valid, err := extn.ValidateOV(key)
	if !valid { // drop packet because OV is not valid
		o.rp.Logger.Info(err.String())
		o.rp.Logger.Info(fmt.Sprintln("Dropped packet, invalid OV"))
		return HookError, err
	}
	o.rp.Logger.Info(fmt.Sprintf("Validated OVi with key %v", key.String()))
	updatedMeta, err := extn.UpdateMeta(meta)
	o.rp.Logger.Info(fmt.Sprintf("Updated Meta from %v to %v", meta, updatedMeta))
	o.SetMeta(updatedMeta)
	o.rp.Logger.Info("Processed OPT hook")
	return HookContinue, nil
}

// Meta returns a slice of the underlying buffer
func (o *rOPTExt) Meta() (common.RawBytes, *common.Error) {
	l, h, err := o.limitsMeta()
	if err != nil {
		return nil, err
	}
	return o.raw[l:h], nil
}

// Set the Meta field directly in the underlying buffer
func (o *rOPTExt) SetMeta(meta common.RawBytes) *common.Error {
	Meta, err := o.Meta()
	if err != nil {
		return err
	}
	if len(Meta) != len(meta) {
		return common.NewError("Invalid meta field length", "expected", len(Meta), "actual", len(meta))
	}
	copy(Meta, meta)
	return nil
}

// Timestamp returns a slice of the underlying buffer
func (o *rOPTExt) Timestamp() (common.RawBytes, *common.Error) {
	l, h, err := o.limitsTimestamp()
	if err != nil {
		return nil, err
	}
	return o.raw[l:h], nil
}

// Set the Timestamp directly in the underlying buffer
func (o *rOPTExt) SetTimestamp(timestamp common.RawBytes) *common.Error {
	Timestamp, err := o.Timestamp()
	if err != nil {
		return err
	}
	if len(Timestamp) != len(timestamp) {
		return common.NewError("Invalid timestamp length", "expected", len(Timestamp), "actual", len(timestamp))
	}
	copy(Timestamp, timestamp)
	return nil
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
	Datahash, err := o.Datahash()
	if err != nil {
		return err
	}
	if len(Datahash) != len(datahash) {
		return common.NewError("Invalid datahash length", "expected", len(Datahash), "actual", len(datahash))
	}
	copy(Datahash, datahash)
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
		return common.NewError("Invalid SessionID length", "expected", len(session), "actual", len(sessionID))
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
	PVF, err := o.PVF()
	if err != nil {
		return err
	}
	if len(PVF) != len(pathVerificationField) {
		return common.NewError("Invalid PVF length", "expected", len(PVF), "actual", len(pathVerificationField))
	}
	copy(PVF, pathVerificationField)
	return nil
}

// Set the OVs directly in the underlying buffer
func (o *rOPTExt) SetOVs(originValidationFields common.RawBytes) *common.Error {
	OVs, err := o.OVs()
	if err != nil {
		return err
	}
	if len(originValidationFields)%opt.OVLength == 0 {
		return common.NewError("Invalid OVs length", "expected a mutiple of ", opt.OVLength, "actual", len(originValidationFields))
	}
	copy(OVs, originValidationFields)
	return nil
}

// OVs returns a slice of the underlying buffer
func (o *rOPTExt) OVs() (common.RawBytes, *common.Error) {
	l, _, err := o.limitsOVs()
	if err != nil {
		return nil, err
	}
	return o.raw[l:], nil
}

// calcDRKey calculates the DRKey for this packet.
func (o *rOPTExt) calcOPTDRKey() (common.RawBytes, *common.Error) {
	in := make(common.RawBytes, 16)
	common.Order.PutUint32(in, uint32(o.rp.srcIA.I))
	common.Order.PutUint32(in[4:], uint32(o.rp.srcIA.A))

	o.rp.Logger.Info(fmt.Sprintf("Packet source %v, packet destination %v", o.rp.srcHost, o.rp.dstHost))
	mac := o.rp.Ctx.Conf.DRKeyPool.Get().(hash.Hash)
	key, err := util.Mac(mac, in)
	// o.rp.Logger.Info(fmt.Sprintf("FirstOrder: %v", key))
	o.rp.Ctx.Conf.DRKeyPool.Put(mac)

	if err != nil {
		return nil, err
	}

	mac, err = util.InitMac(key)
	if err != nil {
		return nil, err
	}

	inputType, err := drkey.InputTypeFromHostTypes(o.rp.dstHost.Type(), o.rp.dstHost.Type())
	size := 16
	if inputType.RequiredLength() > (size - 1 - 1 - 3) {
		size = 32
	}

	in = make(common.RawBytes, size)
	in[0] = uint8(inputType)
	in[1] = uint8(len("OPT"))
	copy(in[2:5], []byte("OPT"))
	copy(in[5:9], o.rp.srcHost.Pack())
	copy(in[9:13], o.rp.dstHost.Pack())
	secondOrderKey, err := util.Mac(mac, in)
	// o.rp.Logger.Info(fmt.Sprintf("Computed second order DRKey: %v over input %v with key %v", secondOrderKey, in, key))
	mac, err = util.InitMac(secondOrderKey)
	in, _ = o.SessionID()
	protoDRKey, err := util.Mac(mac, in)
	// o.rp.Logger.Info(fmt.Sprintf("Computed protoDRKey %v with key %v over blank SessionID", protoDRKey, secondOrderKey))
	return protoDRKey, err
}

// GetExtn returns the opt.Extn representation,
// which does not have direct access to the underlying buffer.
func (o *rOPTExt) GetExtn() (common.Extension, *common.Error) {
	extn, err := opt.NewExtn()
	if err != nil {
		return nil, err
	}
	meta, err := o.Meta()
	if err != nil {
		return nil, err
	}
	extn.SetMeta(meta)
	datahash, err := o.Datahash()
	if err != nil {
		return nil, err
	}
	extn.SetDatahash(datahash)
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

func (o *rOPTExt) String() string {
	// retrieve string representation via opt.Extn
	extn, err := o.GetExtn()
	if err != nil {
		return fmt.Sprintf("SCIONOriginPathTrace - %v: %v", err.Desc, err.String())
	}
	return extn.String()
}

// limitsMeta returns the limits of the Meta field in the raw buffer
func (o *rOPTExt) limitsMeta() (int, int, *common.Error) {
	size := opt.MetaLength
	return 0, 0 + size, nil
}

// limitsTimestmap returns the limits of the Timestamp in the raw buffer
func (o *rOPTExt) limitsTimestamp() (int, int, *common.Error) {
	size := opt.TimestampLength
	_, l, _ := o.limitsMeta()
	return l, l + size, nil
}

// limitsDatahash returns the limits of the Datahash in the raw buffer
func (o *rOPTExt) limitsDatahash() (int, int, *common.Error) {
	size := opt.DatahashLength
	_, l, _ := o.limitsTimestamp()
	return l, l + size, nil
}

// limitsSessionID returns the limits of the SessionID in the raw buffer
func (o *rOPTExt) limitsSessionID() (int, int, *common.Error) {
	size := opt.SessionIDLength
	_, l, _ := o.limitsDatahash()
	return l, l + size, nil
}

// limitsPVF returns the limits of the PVF in the raw buffer
func (o *rOPTExt) limitsPVF() (int, int, *common.Error) {
	size := opt.PVFLength
	_, l, _ := o.limitsSessionID()
	return l, l + size, nil
}

// OVs returns the limits of the OVs in the raw buffer
func (o *rOPTExt) limitsOVs() (int, int, *common.Error) {
	_, l, _ := o.limitsPVF()
	return l, -1, nil
}
