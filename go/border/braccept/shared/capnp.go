// Copyright 2019 ETH Zurich
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

package shared

import (
	"context"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/proto"
)

func CtrlCapnpEnc(signer ctrl.Signer, instance proto.Cerealizable) (common.RawBytes, error) {
	cpld, err := ctrl.NewPld(instance, nil)
	if err != nil {
		return nil, err
	}
	scpld, err := cpld.SignedPld(signer)
	if err != nil {
		return nil, err
	}
	pld, err := scpld.PackPld()
	if err != nil {
		return nil, err
	}
	return pld, nil
}

func CtrlCapnpDec(sigVerifier ctrl.SigVerifier, raw common.RawBytes) (proto.Cerealizable, error) {
	scPld, err := ctrl.NewSignedPldFromRaw(raw)
	if err != nil {
		return nil, err
	}
	if err := sigVerifier.Verify(context.Background(), scPld); err != nil {
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
	return u, nil
}
