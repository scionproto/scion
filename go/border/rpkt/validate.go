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

package rpkt

import (
	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorTotalLenTooLong = "Total length specified in common header doesn't match bytes received"
	ErrorCurrIntfInvalid = "Invalid current interface"
	ErrorIntfRevoked     = "Interface revoked"
	ErrorHookResponse    = "Extension hook return value unrecognised"
)

func (rp *RPkt) Validate() *util.Error {
	// TODO(kormat): verify rest of common header, etc
	if int(rp.CmnHdr.TotalLen) != len(rp.Raw) {
		return util.NewError(ErrorTotalLenTooLong,
			"totalLen", rp.CmnHdr.TotalLen, "max", len(rp.Raw))
	}
	if _, ok := conf.C.Net.IFs[*rp.ifCurr]; !ok {
		return util.NewError(ErrorCurrIntfInvalid, "ifid", *rp.ifCurr)
	}
	conf.C.IFStates.RLock()
	info, ok := conf.C.IFStates.M[*rp.ifCurr]
	conf.C.IFStates.RUnlock()
	if ok && !info.Active() {
		// If the destination is this router, then ignore revocation.
		intf := conf.C.Net.IFs[*rp.ifCurr]
		var intfHost addr.HostAddr
		if rp.DirFrom == DirExternal {
			intfHost = addr.HostFromIP(intf.IFAddr.PublicAddr().IP)
		} else {
			intfHost = addr.HostFromIP(conf.C.Net.LocAddr[intf.LocAddrIdx].PublicAddr().IP)
		}
		if !(*rp.dstIA == *conf.C.IA && addr.HostEq(rp.dstHost, intfHost)) {
			return util.NewError(ErrorIntfRevoked, "ifid", *rp.ifCurr)
		}
	}
	if err := rp.validatePath(rp.DirFrom); err != nil {
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
			return util.NewError(ErrorHookResponse, "hook", "Validate", "idx", i, "val", ret)
		}
	}
	return nil
}
