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

// Package ctrl handles SCION control-plane payloads, which are encoded as capnp proto messages.
// Each ctrl payload has a 4B length field prefixed to the start of the capnp message.
package ctrl

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	union
	*Data
}

// NewPld creates a new control payload, containing the supplied Cerealizable instance.
func NewPld(u proto.Cerealizable, d *Data) (*Pld, error) {
	p := &Pld{Data: d}
	return p, p.union.set(u)
}

// NewPathMgmtPld creates a new control payload, containing a new path_mgmt payload,
// which in turn contains the supplied Cerealizable instance.
func NewPathMgmtPld(u proto.Cerealizable, pathD *path_mgmt.Data, ctrlD *Data) (*Pld, error) {
	ppld, err := path_mgmt.NewPld(u, pathD)
	if err != nil {
		return nil, err
	}
	return NewPld(ppld, ctrlD)
}

// NewCertMgmtPld creates a new control payload, containing a new cert_mgmt payload,
// which in turn contains the supplied Cerealizable instance.
func NewCertMgmtPld(u proto.Cerealizable, certD *cert_mgmt.Data, ctrlD *Data) (*Pld, error) {
	cpld, err := cert_mgmt.NewPld(u, certD)
	if err != nil {
		return nil, err
	}
	return NewPld(cpld, ctrlD)
}

func NewPldFromRaw(b common.RawBytes) (*Pld, error) {
	p := &Pld{Data: &Data{}}
	return p, proto.ParseFromRaw(p, proto.CtrlPld_TypeID, b)
}

func (p *Pld) Union() (proto.Cerealizable, error) {
	return p.union.get()
}

// GetCertMgmt returns the CertMgmt payload and the CtrlPld's non-union Data.
// If the union type is not CertMgmt, an error is returned.
func (p *Pld) GetCertMgmt() (*cert_mgmt.Pld, *Data, error) {
	u, err := p.Union()
	if err != nil {
		return nil, nil, err
	}
	certP, ok := u.(*cert_mgmt.Pld)
	if !ok {
		return nil, nil, common.NewBasicError("Non-matching ctrl pld contents", nil,
			"expected", "*cert_mgmt.Pld", "actual", common.TypeOf(u))
	}
	return certP, p.Data, nil
}

// GetPathMgmt returns the PathMgmt payload and the CtrlPld's non-union Data.
// If the union type is not PathMgmt, an error is returned.
func (p *Pld) GetPathMgmt() (*path_mgmt.Pld, *Data, error) {
	u, err := p.Union()
	if err != nil {
		return nil, nil, err
	}
	pathP, ok := u.(*path_mgmt.Pld)
	if !ok {
		return nil, nil, common.NewBasicError("Non-matching ctrl pld contents", nil,
			"expected", "*path_mgmt.Pld", "actual", common.TypeOf(u))
	}
	return pathP, p.Data, nil
}

func (p *Pld) Len() int {
	return -1
}

func (p *Pld) Copy() (*Pld, error) {
	raw, err := proto.PackRoot(p)
	if err != nil {
		return nil, err
	}
	return NewPldFromRaw(raw)
}

func (p *Pld) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(p, b)
}

func (p *Pld) SignedPld(signer Signer) (*SignedPld, error) {
	return NewSignedPld(p, signer)
}

func (p *Pld) ProtoId() proto.ProtoIdType {
	return proto.CtrlPld_TypeID
}

func (p *Pld) String() string {
	desc := []string{"Ctrl: Union:"}
	u, err := p.Union()
	if err != nil {
		desc = append(desc, err.Error())
	} else {
		desc = append(desc, fmt.Sprintf("%+v", u))
	}
	return strings.Join(desc, " ")
}

// Data holds all non-union entries from CtrlPld
type Data struct {
	ReqId   uint64
	TraceId common.RawBytes
}
