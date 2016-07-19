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

package packet

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

func (p *Packet) SrcIA() (*addr.ISD_AS, *util.Error) {
	if p.srcIA == nil {
		var err *util.Error
		p.srcIA, err = p.hookIA(p.hooks.SrcIA, p.idxs.srcIA)
		if err != nil {
			return nil, util.NewError(ErrorGetSrcIA, "err", err)
		}
	}
	return p.srcIA, nil
}

func (p *Packet) DstIA() (*addr.ISD_AS, *util.Error) {
	if p.dstIA == nil {
		var err *util.Error
		p.dstIA, err = p.hookIA(p.hooks.DstIA, p.idxs.dstIA)
		if err != nil {
			return nil, util.NewError(ErrorGetDstIA, "err", err)
		}
	}
	return p.dstIA, nil
}

func (p *Packet) hookIA(hooks []HookIA, idx int) (*addr.ISD_AS, *util.Error) {
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
	return addr.IAFromRaw(p.Raw[idx:]), nil
}

func (p *Packet) SrcHost() (addr.HostAddr, *util.Error) {
	if p.srcHost == nil {
		var err *util.Error
		p.srcHost, err = p.hookHost(p.hooks.SrcHost, p.idxs.srcHost, p.CmnHdr.SrcType)
		if err != nil {
			return nil, util.NewError(ErrorGetSrcHost, "err", err)
		}
	}
	return p.srcHost, nil
}

func (p *Packet) DstHost() (addr.HostAddr, *util.Error) {
	if p.dstHost == nil {
		var err *util.Error
		p.dstHost, err = p.hookHost(p.hooks.DstHost, p.idxs.dstHost, p.CmnHdr.DstType)
		if err != nil {
			return nil, util.NewError(ErrorGetDstHost, "err", err)
		}
	}
	return p.dstHost, nil
}

func (p *Packet) hookHost(
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
	return addr.HostFromRaw(p.Raw[idx:], htype)
}
