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

package tpkt

import (
	"context"
	"fmt"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/proto"
)

var _ LayerBuilder = (*PathMgmtPld)(nil)
var _ LayerMatcher = (*PathMgmtPld)(nil)

type PathMgmtPld struct {
	Signer      ctrl.Signer
	SigVerifier ctrl.SigVerifier
	Instance    proto.Cerealizable
}

func (l *PathMgmtPld) LayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (l *PathMgmtPld) Build() ([]gopacket.SerializableLayer, error) {
	return []gopacket.SerializableLayer{l}, nil
}

func (l *PathMgmtPld) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	cpld, err := ctrl.NewPathMgmtPld(l.Instance, nil, nil)
	if err != nil {
		return err
	}
	scpld, err := cpld.SignedPld(l.Signer)
	if err != nil {
		return err
	}
	pld, err := scpld.PackPld()
	if err != nil {
		return err
	}
	buf, err := b.PrependBytes(len(pld))
	if err != nil {
		return err
	}
	copy(buf, pld)
	return nil
}

func (l *PathMgmtPld) Match(pktLayers []gopacket.Layer, lc *LayerCache) ([]gopacket.Layer, error) {
	b := pktLayers[0].(*gopacket.Payload)
	scPld, err := ctrl.NewSignedPldFromRaw(b.Payload())
	if err != nil {
		return nil, err
	}
	if err := l.SigVerifier.Verify(context.Background(), scPld); err != nil {
		return nil, err
	}
	cPld, err := scPld.Pld()
	if err != nil {
		return nil, err
	}
	u, err := cPld.Union()
	if err != nil {
		return nil, err
	}
	pld, ok := u.(*path_mgmt.Pld)
	if !ok {
		return nil, fmt.Errorf("Not a PathMgmtPld, actual %s", common.TypeOf(cPld))
	}
	if u, err = pld.Union(); err != nil {
		return nil, err
	}
	if l.Instance.ProtoId() != u.ProtoId() {
		return nil, fmt.Errorf("Wrong instance type, expected: %s, actual: %s",
			common.TypeOf(l.Instance), common.TypeOf(u))
	}
	return nil, nil
}
