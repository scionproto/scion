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

package topology

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

type Diff int

const (
	DiffNone Diff = iota
	DiffAdded
	DiffRemoved
	DiffChanged
)

func (d Diff) String() string {
	switch d {
	case DiffNone:
		return "None"
	case DiffAdded:
		return "Added"
	case DiffRemoved:
		return "Removed"
	case DiffChanged:
		return "Changed"
	}
	return fmt.Sprintf("UNKNOWN (%d)", d)
}

// BRDiff indicates the differences between two border router entries.
// The fields CtrlAddrs, InternalAddrs, IFIDs are only set if Diff
// equals DiffChanged.
type BRDiff struct {
	// Diff indicates whether the border router is added, removed,
	// or parts of the entry changed.
	Diff Diff
	// CtrlAddrs indicates if the CtrlAddrs changed.
	CtrlAddrs Diff
	// InternalAddrs indicates if the InternalAddrs changed.
	InternalAddrs Diff
	// IFIDs contains all interfaces ids of added, removed or changed interfaces.
	IFIDs map[common.IFIDType]Diff
}

// Empty indicates whether the difference is empty.
func (b BRDiff) Empty() bool {
	return b.Diff == DiffNone && b.CtrlAddrs == DiffNone &&
		b.InternalAddrs == DiffNone && len(b.IFIDs) == 0
}

// TopoDiff holds the differences between two topologies.
type TopoDiff struct {
	Timestamp      Diff
	TimestampHuman Diff
	TTL            Diff
	ISD_AS         Diff
	Overlay        Diff
	MTU            Diff
	Core           Diff

	BR        map[string]BRDiff
	IFInfoMap map[common.IFIDType]Diff

	BS  map[string]Diff
	CS  map[string]Diff
	PS  map[string]Diff
	SB  map[string]Diff
	RS  map[string]Diff
	DS  map[string]Diff
	SIG map[string]Diff
	ZK  map[int]Diff
}

// GetSvc returns the diff for the specified service.
func (d *TopoDiff) GetSvc(svc proto.ServiceType) (map[string]Diff, error) {
	switch svc {
	case proto.ServiceType_unset:
		return nil, common.NewBasicError("Service type unset", nil)
	case proto.ServiceType_bs:
		return d.BS, nil
	case proto.ServiceType_ps:
		return d.PS, nil
	case proto.ServiceType_cs:
		return d.CS, nil
	case proto.ServiceType_sb:
		return d.SB, nil
	case proto.ServiceType_sig:
		return d.SIG, nil
	case proto.ServiceType_ds:
		return d.DS, nil
	default:
		return nil, common.NewBasicError("Unsupported service type", nil, "type", svc)
	}
}

// Empty indicates whether the difference is empty. If ignoreTime is set,
// Timestamp, TimestampHuman and TTL are ignored.
func (d *TopoDiff) Empty(ignoreTime bool) bool {
	e := d.ISD_AS == DiffNone &&
		d.Overlay == DiffNone &&
		d.MTU == DiffNone &&
		d.Core == DiffNone &&
		len(d.BR) == 0 &&
		len(d.IFInfoMap) == 0 &&
		len(d.BS) == 0 &&
		len(d.CS) == 0 &&
		len(d.PS) == 0 &&
		len(d.SB) == 0 &&
		len(d.RS) == 0 &&
		len(d.DS) == 0 &&
		len(d.SIG) == 0 &&
		len(d.ZK) == 0
	if ignoreTime {
		return e
	}
	return e && d.TTL == DiffNone && d.Timestamp == DiffNone && d.TimestampHuman == DiffNone
}

// Compare compares topology a to topology b. Entries that are present
// in topology a and absent in topology b are labeled as 'DiffAdded'.
// Entries absent in topology a and present in topology b are labeled
// as 'DiffRemoved'.
func Compare(a, b *Topo) *TopoDiff {
	diff := &TopoDiff{
		Timestamp:      diffFromEq(a.Timestamp.Equal(b.Timestamp)),
		TimestampHuman: diffFromEq(a.TimestampHuman == b.TimestampHuman),
		TTL:            diffFromEq(a.TTL == b.TTL),
		ISD_AS:         diffFromEq(a.ISD_AS.Eq(b.ISD_AS)),
		Overlay:        diffFromEq(a.Overlay == b.Overlay),
		MTU:            diffFromEq(a.MTU == b.MTU),
		Core:           diffFromEq(a.Core == b.Core),
		IFInfoMap:      CompareIFInfoMap(a.IFInfoMap, b.IFInfoMap),
		BS:             CompareSvc(a.BS, b.BS),
		CS:             CompareSvc(a.CS, b.CS),
		PS:             CompareSvc(a.PS, b.PS),
		SB:             CompareSvc(a.SB, b.SB),
		RS:             CompareSvc(a.RS, b.RS),
		DS:             CompareSvc(a.DS, b.DS),
		SIG:            CompareSvc(a.SIG, b.SIG),
		ZK:             CompareZk(a.ZK, b.ZK),
	}
	diff.BR = CompareBR(a.BR, b.BR, diff.IFInfoMap)
	return diff
}

// CompareIFInfoMap compares interface infos map a to b. The returned map
// contains all added, removed or changed interfaces. An interface is labeled
// added if it is present in a and absent in b. An interface is labeled removed
// if it is absent in a and present in b.
func CompareIFInfoMap(a, b IfInfoMap) map[common.IFIDType]Diff {
	diff := make(map[common.IFIDType]Diff)
	for id, info := range a {
		otherInfo, ok := b[id]
		if !ok {
			diff[id] = DiffAdded
		} else if intfChanged(info, otherInfo) {
			diff[id] = DiffChanged
		}
	}
	for id := range b {
		if _, ok := a[id]; !ok {
			diff[id] = DiffRemoved
		}
	}
	return diff
}

// intfChanged compares the interface info. The ctrl and internal address
// are ignored.
func intfChanged(a, b IFInfo) bool {
	return a.BRName != b.BRName ||
		a.Overlay != b.Overlay ||
		!a.Local.Equal(b.Local) ||
		!a.Remote.Eq(b.Remote) ||
		a.RemoteIFID != b.RemoteIFID ||
		a.Bandwidth != b.Bandwidth ||
		!a.ISD_AS.Eq(b.ISD_AS) ||
		a.LinkType != b.LinkType ||
		a.MTU != b.MTU
}

// CompareSvc compares the service map a to b. The returned map contains
// the element ids of all added, removed or changed services. A service is
// labeled added if it is present in a and absent in b. A service is labeled
// removed if it is absent in a and present in b.
func CompareSvc(a, b IDAddrMap) map[string]Diff {
	diff := make(map[string]Diff)
	for id, addr := range a {
		otherAddr, ok := b[id]
		if !ok {
			diff[id] = DiffAdded
		} else if !addr.Equal(&otherAddr) {
			diff[id] = DiffChanged
		}
	}
	for id := range b {
		if _, ok := a[id]; !ok {
			diff[id] = DiffRemoved
		}
	}
	return diff
}

// CompareZk compares the zookeeper map a to b. The returned map contains
// the ids of all added, removed or changed zookeeper instances. An instance
// is labeled added if it is present in a and absent in b. An instance is
// labeled removed if it is absent in a and present in b.
func CompareZk(a, b map[int]*addr.AppAddr) map[int]Diff {
	diff := make(map[int]Diff)
	for id, addr := range a {
		otherAddr, ok := b[id]
		if !ok {
			diff[id] = DiffAdded
		} else if !addr.Eq(otherAddr) {
			diff[id] = DiffChanged
		}
	}
	for id := range b {
		if _, ok := a[id]; !ok {
			diff[id] = DiffRemoved
		}
	}
	return diff
}

// CompareBR compares the border router map a to b. The returned map contains
// the ids of all added, removed or changed border routers. A border router
// is labeled added if it is present in a and absent in b. A border router is
// labeled removed if it is absent in a and present in b.
func CompareBR(a, b map[string]BRInfo, intfDiff map[common.IFIDType]Diff) map[string]BRDiff {
	comp := brComp{
		diff:     make(map[string]BRDiff),
		intfDiff: intfDiff,
		a:        a,
		b:        b,
	}
	return comp.compare()
}

type brComp struct {
	diff     map[string]BRDiff
	intfDiff map[common.IFIDType]Diff
	a        map[string]BRInfo
	b        map[string]BRInfo
}

func (c brComp) compare() map[string]BRDiff {
	for id, info := range c.a {
		otherInfo, ok := c.b[id]
		if !ok {
			c.diff[id] = BRDiff{Diff: DiffAdded}
		} else {
			c.compExisting(id, info, otherInfo)
		}
	}
	for id := range c.b {
		if _, ok := c.a[id]; !ok {
			c.diff[id] = BRDiff{Diff: DiffRemoved}
		}
	}
	return c.diff
}

func (c brComp) compExisting(id string, info, otherInfo BRInfo) {
	diff := BRDiff{
		CtrlAddrs:     diffFromEq(info.CtrlAddrs.Equal(otherInfo.CtrlAddrs)),
		InternalAddrs: diffFromEq(info.InternalAddrs.Equal(otherInfo.InternalAddrs)),
		IFIDs:         make(map[common.IFIDType]Diff),
	}
	for _, id := range info.IFIDs {
		if !containsIntf(id, otherInfo.IFIDs) {
			diff.IFIDs[id] = DiffAdded
		} else if c.intfDiff[id] != DiffNone {
			diff.IFIDs[id] = DiffChanged
		}
	}
	for _, id := range otherInfo.IFIDs {
		if !containsIntf(id, info.IFIDs) {
			diff.IFIDs[id] = DiffRemoved
		}
	}
	if !diff.Empty() {
		if diff.Diff == DiffNone {
			diff.Diff = DiffChanged
		}
		c.diff[id] = diff
	}
}

func containsIntf(ifid common.IFIDType, ifids []common.IFIDType) bool {
	for _, i := range ifids {
		if ifid == i {
			return true
		}
	}
	return false
}

func diffFromEq(equal bool) Diff {
	if equal {
		return DiffNone
	}
	return DiffChanged
}
