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
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

const (
	ErrorGetSrcIA   = "Unable to retrieve source ISD-AS"
	ErrorGetDstIA   = "Unable to retrieve destination ISD-AS"
	ErrorGetSrcHost = "Unable to retrieve source host"
	ErrorGetDstHost = "Unable to retrieve destination host"
)

func (rp *RtrPkt) SrcIA() (*addr.ISD_AS, *common.Error) {
	if rp.srcIA == nil {
		var err *common.Error
		rp.srcIA, err = rp.hookIA(rp.hooks.SrcIA, rp.idxs.srcIA)
		if err != nil {
			return nil, common.NewError(ErrorGetSrcIA, "err", err)
		}
	}
	return rp.srcIA, nil
}

func (rp *RtrPkt) DstIA() (*addr.ISD_AS, *common.Error) {
	if rp.dstIA == nil {
		var err *common.Error
		rp.dstIA, err = rp.hookIA(rp.hooks.DstIA, rp.idxs.dstIA)
		if err != nil {
			return nil, common.NewError(ErrorGetDstIA, "err", err)
		}
	}
	return rp.dstIA, nil
}

func (rp *RtrPkt) hookIA(hooks []HookIA, idx int) (*addr.ISD_AS, *common.Error) {
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

func (rp *RtrPkt) SrcHost() (addr.HostAddr, *common.Error) {
	if rp.srcHost == nil {
		var err *common.Error
		rp.srcHost, err = rp.hookHost(rp.hooks.SrcHost, rp.idxs.srcHost, rp.CmnHdr.SrcType)
		if err != nil {
			return nil, common.NewError(ErrorGetSrcHost, "err", err)
		}
	}
	return rp.srcHost, nil
}

func (rp *RtrPkt) DstHost() (addr.HostAddr, *common.Error) {
	if rp.dstHost == nil {
		var err *common.Error
		rp.dstHost, err = rp.hookHost(rp.hooks.DstHost, rp.idxs.dstHost, rp.CmnHdr.DstType)
		if err != nil {
			return nil, common.NewError(ErrorGetDstHost, "err", err)
		}
	}
	return rp.dstHost, nil
}

func (rp *RtrPkt) hookHost(
	hooks []HookHost, idx int, htype uint8) (addr.HostAddr, *common.Error) {
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
