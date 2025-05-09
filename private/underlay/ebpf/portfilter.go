// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 SCION Association
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

package ebpf

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gopacket/gopacket/afpacket"
)

// FilterHandle holds both filters and keeps them alive until Closed. prog is the SockFilter
// program and link refers to the traffic control filter for the kernel stack. As long as such an
// object exists, the two filters remain active.
type FilterHandle struct {
	kLink link.Link
	kObjs *ebpf.Collection
	sObjs *ebpf.Collection
}

// Close causes both filters to go away.
func (fh *FilterHandle) Close() {
	fh.kLink.Close()
	fh.kObjs.Close()
	fh.sObjs.Close()
}

func (fh *FilterHandle) Info() (*link.Info, error) {
	return fh.kLink.Info()
}

// Loads a port filter bpf socket filter program that only allows UDP traffic to the given port
// number. This function returns a file descriptor referencing the loaded program (and indirectly,
// the associated map). This program can then be attached to a (typically raw) socket and will
// filter the traffic to be delivered to that socket. (For example, with Go TPacket:
// myTpacketHandle.SetEBPF(filter_fd). When the socket is closed the program and its
// map are discarded by the kernel.
//
// Note that multiple filters could end-up attached to the same network interface. This should work
// but it would be more efficient to discover that a filter is already in place and simply expand
// its table. An embelishment for later,
//
// For any of this to work, the calling process must have the following capabilities:
// cap_bpf, cap_net_admin, cap_net_raw. For example, the buildfile applies to following command
// to the portfilter_test executable:
//
//	/usr/bin/sudo setcap "cap_bpf+ep cap_net_admin+ep cap_net_raw+ep" $@
func bpfKFilter(ifIndex int, port uint16) (link.Link, *ebpf.Collection, error) {
	spec, err := loadKfilter()
	if err != nil {
		return nil, nil, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, err
	}
	// We only need the collection to initialize stuff.
	defer coll.Close()

	// We keep the program.
	prog := coll.Programs["bpf_k_filter"]
	if prog == nil {
		panic("no program named bpf_k_filter found")
	}

	// Now load the map and populate it with our port mapping.
	myMap := coll.Maps["k_map_flt"]
	if myMap == nil {
		panic(fmt.Errorf("no map named k_map_flt found"))
	}

	// map.Put plays crystal ball with key and value so it accepts either
	// pointers or values.
	idx := uint32(0)
	portNbo := htons(port)
	if err := myMap.Put(idx, portNbo); err != nil {
		panic(fmt.Sprintf("error: %v, key=%p, val=%p\n", err, &idx, &portNbo))
	}

	// Attach the program to the interface. We attach it at head; it has almost zero cost.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifIndex,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Head(),
	})

	return l, coll, nil
}

func bpfSockFilter(afp *afpacket.TPacket, port uint16) (*ebpf.Collection, error) {
	spec, err := loadSockfilter()
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}
	// We only need the collection to initialize stuff.
	defer coll.Close()

	// We keep the program, so the collection can be closed without closing the program.
	prog := coll.Programs["bpf_sock_filter"]
	if prog == nil {
		panic("no program named pbf_sock_filter found")
	}

	// Now load the map and populate it with our port mapping.
	myMap := coll.Maps["sock_map_flt"]
	if myMap == nil {
		panic(fmt.Errorf("no map named sock_map_flt found"))
	}

	// map.Put plays crystal ball with key and value so it accepts either
	// pointers or values.
	idx := uint32(0)
	portNbo := htons(port)
	if err := myMap.Put(idx, portNbo); err != nil {
		panic(fmt.Sprintf("error: %v, key=%p, val=%p\n", err, &idx, &portNbo))
	}

	err = afp.SetEBPF(int32(prog.FD()))
	if err != nil {
		prog.Close()
		return nil, err
	}

	return coll, nil
}

// BpfPortFilter: attaches a SCHED_CLS program to the network interface "ifIndex" and a SOCK_FILTER
// program to the raw socket "afp". The SCHED_CLS program filters all traffic to port "port" from
// interface "ifIndex" out of the kernel networking stack. The SOCK_FILTER program only allows
// traffic to port "port" to reach the socket referred to by "afp".
//
// Returns: a handle referring to both programs. Calling the handle's Close() method will discard
// the programs.
func BpfPortFilter(
	ifIndex int,
	afp *afpacket.TPacket,
	port uint16,
) (*FilterHandle, error) {
	kLink, kObjs, err := bpfKFilter(ifIndex, port)
	if err != nil {
		return nil, err
	}

	sObjs, err := bpfSockFilter(afp, port)
	if err != nil {
		kLink.Close()
		return nil, err
	}

	return &FilterHandle{
		kLink: kLink,
		kObjs: kObjs,
		sObjs: sObjs,
	}, nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
