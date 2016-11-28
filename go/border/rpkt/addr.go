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

// This file handles parsing the SCION address header.

package rpkt

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

// SrcIA retrieves the source ISD-AS if it isn't already known.
func (rp *RtrPkt) SrcIA() (*addr.ISD_AS, *common.Error) {
	if rp.srcIA == nil {
		var err *common.Error
		rp.srcIA, err = rp.hookIA(rp.hooks.SrcIA, rp.idxs.srcIA)
		if err != nil {
			return nil, common.NewError("Unable to retrieve source ISD-AS", "err", err)
		}
	}
	return rp.srcIA, nil
}

// DstIA retrieves the destination ISD-AS if it isn't already known.
func (rp *RtrPkt) DstIA() (*addr.ISD_AS, *common.Error) {
	if rp.dstIA == nil {
		var err *common.Error
		rp.dstIA, err = rp.hookIA(rp.hooks.DstIA, rp.idxs.dstIA)
		if err != nil {
			return nil, common.NewError("Unable to retrieve destination ISD-AS", "err", err)
		}
	}
	return rp.dstIA, nil
}

// hookIA is a helper method used by SrcIA/DstIA to run ISD-AS retrieval hooks,
// falling back to parsing the address header directly otherwise.
func (rp *RtrPkt) hookIA(hooks []hookIA, idx int) (*addr.ISD_AS, *common.Error) {
	for _, f := range hooks {
		ret, ia, err := f()
		switch {
		case err != nil:
			return nil, err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			return ia, nil
		}
	}
	return addr.IAFromRaw(rp.Raw[idx:]), nil
}

// SrcHost retrieves the source host address if it isn't already known.
func (rp *RtrPkt) SrcHost() (addr.HostAddr, *common.Error) {
	if rp.srcHost == nil {
		var err *common.Error
		rp.srcHost, err = rp.hookHost(rp.hooks.SrcHost, rp.idxs.srcHost, rp.CmnHdr.SrcType)
		if err != nil {
			return nil, common.NewError("Unable to retrieve source host", "err", err)
		}
	}
	return rp.srcHost, nil
}

// DstHost retrieves the destination host address if it isn't already known.
func (rp *RtrPkt) DstHost() (addr.HostAddr, *common.Error) {
	if rp.dstHost == nil {
		var err *common.Error
		rp.dstHost, err = rp.hookHost(rp.hooks.DstHost, rp.idxs.dstHost, rp.CmnHdr.DstType)
		if err != nil {
			return nil, common.NewError("Unable to retrieve destination host", "err", err)
		}
	}
	return rp.dstHost, nil
}

// hookHost is a helper method used by SrcHost/DstHost to run host address
// retrieval hooks, falling back to parsing the address header directly
// otherwise.
func (rp *RtrPkt) hookHost(
	hooks []hookHost, idx int, htype uint8) (addr.HostAddr, *common.Error) {
	for _, f := range hooks {
		ret, host, err := f()
		switch {
		case err != nil:
			return nil, err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			return host, nil
		}
	}
	return addr.HostFromRaw(rp.Raw[idx:], htype)
}
