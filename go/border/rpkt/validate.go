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
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
)

const (
	errCurrIntfInvalid = "Invalid current interface"
	errIntfRevoked     = "Interface revoked"
	errHookResponse    = "Extension hook return value unrecognised"
)

// Validate performs basic validation of a packet, including calling any
// registered validation hooks.
func (rp *RtrPkt) Validate() error {
	intf, ok := rp.Ctx.Conf.Net.IFs[*rp.ifCurr]
	if !ok {
		return common.NewCError(errCurrIntfInvalid, "ifid", *rp.ifCurr)
	}
	// XXX(kormat): the rest of the common header is checked by the parsing phase.
	if !addr.HostTypeCheck(rp.CmnHdr.DstType) {
		sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadDstType, nil)
		return common.NewCErrorData("Unsupported destination address type", sdata,
			"type", rp.CmnHdr.DstType)
	}
	if !addr.HostTypeCheck(rp.CmnHdr.SrcType) || rp.CmnHdr.SrcType == addr.HostTypeSVC {
		// Either the source address type isn't supported, or it is an SVC
		// address (which is forbidden).
		sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadSrcType, nil)
		return common.NewCErrorData("Unsupported source address type", sdata,
			"type", rp.CmnHdr.SrcType)
	}
	if int(rp.CmnHdr.TotalLen) != len(rp.Raw) {
		sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadPktLen,
			&scmp.InfoPktSize{Size: uint16(len(rp.Raw)), MTU: uint16(intf.MTU)})
		return common.NewCErrorData(
			"Total length specified in common header doesn't match bytes received", sdata,
			"totalLen", rp.CmnHdr.TotalLen, "actual", len(rp.Raw))
	}
	if err := rp.validatePath(rp.DirFrom); err != nil {
		return err
	}
	if err := rp.validateExtns(); err != nil {
		return err
	}
	for i, f := range rp.hooks.Validate {
		ret, err := f()
		switch {
		case err != nil:
			return err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			break
		default:
			return common.NewCError(errHookResponse, "hook", "Validate", "idx", i, "val", ret)
		}
	}
	return nil
}
