// Copyright 2019 Anapaya Systems
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

package beaconing

import (
	"sort"
	"sync"
	"time"

	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

// packBeaconMsg packs the provided beacon and creates a one-hop message.
func packBeaconMsg(bseg *seg.Beacon, ia addr.IA, egIfid common.IFIDType,
	signer infra.Signer) (*onehop.Msg, error) {

	pld, err := ctrl.NewPld(bseg, nil)
	if err != nil {
		return nil, common.NewBasicError("Unable to create payload", err)
	}
	spld, err := pld.SignedPld(signer)
	if err != nil {
		return nil, common.NewBasicError("Unable to sign payload", err)
	}
	packed, err := spld.PackPld()
	if err != nil {
		return nil, common.NewBasicError("Unable to pack payload", err)
	}
	msg := &onehop.Msg{
		Dst: snet.SCIONAddress{
			IA:   ia,
			Host: addr.SvcBS,
		},
		Ifid:     egIfid,
		InfoTime: time.Now(),
		Pld:      packed,
	}
	return msg, nil
}

// sortedIntfs returns two sorted lists. The first list contains all active
// interfaces of the given type. The second list contains all non-active
// interfaces of the given type.
func sortedIntfs(intfs *ifstate.Interfaces, linkType proto.LinkType) ([]common.IFIDType,
	[]common.IFIDType) {

	var active, nonActive []common.IFIDType
	for ifid, intf := range intfs.All() {
		topoInfo := intf.TopoInfo()
		if topoInfo.LinkType != linkType {
			continue
		}
		if intf.State() != ifstate.Active {
			nonActive = append(nonActive, ifid)
			continue
		}
		active = append(active, ifid)
	}
	sort.Slice(active, func(i, j int) bool { return active[i] < active[j] })
	sort.Slice(nonActive, func(i, j int) bool { return nonActive[i] < nonActive[j] })
	return active, nonActive
}

type ctr struct {
	sync.Mutex
	c int
}

func (c *ctr) Inc() {
	c.Lock()
	defer c.Unlock()
	c.c++
}
