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
	"reflect"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/proto"
)

var _ LayerMatcher = (*PathMgmtPld)(nil)

type PathMgmtPld struct {
	SigVerifier ctrl.SigVerifier
	Instance    proto.Cerealizable
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
		return nil, fmt.Errorf("Not a PathMgmtPld", nil, "actual", common.TypeOf(cPld))
	}
	if u, err = pld.Union(); err != nil {
		return nil, err
	}
	if reflect.TypeOf(l.Instance) != reflect.TypeOf(u) {
		return nil, fmt.Errorf("Wrong instance type, expected: %s, actual: %s",
			common.TypeOf(l.Instance), common.TypeOf(u))
	}
	return nil, nil
}
