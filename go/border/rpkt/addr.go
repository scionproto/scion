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
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorGetSrcIA   = "Unable to retrieve source ISD-AS"
	ErrorGetDstIA   = "Unable to retrieve destination ISD-AS"
	ErrorGetSrcHost = "Unable to retrieve source host"
	ErrorGetDstHost = "Unable to retrieve destination host"
)

func (rp *RPkt) SrcIA() (*addr.ISD_AS, *util.Error) {
	if rp.srcIA == nil {
		var err *util.Error
		rp.srcIA, err = rp.hookIA(rp.hooks.SrcIA, rp.idxs.srcIA)
		if err != nil {
			return nil, util.NewError(ErrorGetSrcIA, "err", err)
		}
	}
	return rp.srcIA, nil
}

func (rp *RPkt) DstIA() (*addr.ISD_AS, *util.Error) {
	if rp.dstIA == nil {
		var err *util.Error
		rp.dstIA, err = rp.hookIA(rp.hooks.DstIA, rp.idxs.dstIA)
		if err != nil {
			return nil, util.NewError(ErrorGetDstIA, "err", err)
		}
	}
	return rp.dstIA, nil
}

func (rp *RPkt) hookIA(hooks []HookIA, idx int) (*addr.ISD_AS, *util.Error) {
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

func (rp *RPkt) SrcHost() (addr.HostAddr, *util.Error) {
	if rp.srcHost == nil {
		var err *util.Error
		rp.srcHost, err = rp.hookHost(rp.hooks.SrcHost, rp.idxs.srcHost, rp.CmnHdr.SrcType)
		if err != nil {
			return nil, util.NewError(ErrorGetSrcHost, "err", err)
		}
	}
	return rp.srcHost, nil
}

func (rp *RPkt) DstHost() (addr.HostAddr, *util.Error) {
	if rp.dstHost == nil {
		var err *util.Error
		rp.dstHost, err = rp.hookHost(rp.hooks.DstHost, rp.idxs.dstHost, rp.CmnHdr.DstType)
		if err != nil {
			return nil, util.NewError(ErrorGetDstHost, "err", err)
		}
	}
	return rp.dstHost, nil
}

func (rp *RPkt) hookHost(
	hooks []HookHost, idx int, htype uint8) (addr.HostAddr, *util.Error) {
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
