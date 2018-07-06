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

// This file handles overall validation of packets.

package rpkt

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
)

const (
	errCurrIntfInvalid = "Invalid current interface"
	errIntfRevoked     = "Interface revoked"
	errHookResponse    = "Extension hook return value unrecognised"
)

// Validate performs basic validation of a packet, including calling any
// registered validation hooks. Returns true and no error if validation
// succeeded. On failure due to normal reasons (e.g., filtering), returns false
// and no error. If validation failed due to some exceptional event, returns an
// error.
func (rp *RtrPkt) Validate() (bool, error) {
	// XXX ifCurr would be nil if the packet was received in the internal interface and had no HopF.
	var mtu int
	if rp.ifCurr != nil {
		intf, ok := rp.Ctx.Conf.Net.IFs[*rp.ifCurr]
		if !ok {
			return false, common.NewBasicError(errCurrIntfInvalid, nil, "ifid", *rp.ifCurr)
		}
		mtu = intf.MTU
	} else {
		mtu = rp.Ctx.Conf.Topo.MTU
	}
	// XXX(kormat): the rest of the common header is checked by the parsing phase.
	if !addr.HostTypeCheck(rp.CmnHdr.DstType) {
		return false, common.NewBasicError("Unsupported destination address type",
			scmp.NewError(scmp.C_CmnHdr, scmp.T_C_BadDstType, nil, nil), "type", rp.CmnHdr.DstType)
	}
	if !addr.HostTypeCheck(rp.CmnHdr.SrcType) || rp.CmnHdr.SrcType == addr.HostTypeSVC {
		// Either the source address type isn't supported, or it is an SVC
		// address (which is forbidden).
		return false, common.NewBasicError("Unsupported source address type",
			scmp.NewError(scmp.C_CmnHdr, scmp.T_C_BadSrcType, nil, nil), "type", rp.CmnHdr.SrcType)
	}
	if int(rp.CmnHdr.TotalLen) != len(rp.Raw) {
		return false, common.NewBasicError(
			"Total length specified in common header doesn't match bytes received",
			scmp.NewError(scmp.C_CmnHdr, scmp.T_C_BadPktLen,
				&scmp.InfoPktSize{Size: uint16(len(rp.Raw)), MTU: uint16(mtu)}, nil),
			"totalLen", rp.CmnHdr.TotalLen, "actual", len(rp.Raw),
		)
	}
	// ValidatePath checks that ifCurr is valid
	if err := rp.validatePath(rp.DirFrom); err != nil {
		return false, err
	}
	if err := rp.validateExtns(); err != nil {
		return false, err
	}
	for i, f := range rp.hooks.Validate {
		ret, err := f()
		switch {
		case err != nil:
			return false, err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			return true, nil
		case ret == HookError:
			return false, nil
		default:
			return false, common.NewBasicError(errHookResponse, nil,
				"hook", "Validate", "idx", i, "val", ret)
		}
	}
	return true, nil
}
