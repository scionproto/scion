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
)

// Loads a port filter bpf socket filter program that only allows UDP traffic to the given port
// number. This function returns a file descriptor referencing the loaded program (and indirectly,
// the associated map). This program can then be attached to a (typically raw) socket and will
// filter the traffic to be delivered to that socket. When the socket is closed the program and its
// map are discarded by the kernel.
//
// For any of this to work, the calling process must have the following capabilities:
// cap_bpf, cap_net_admin, cap_net_raw. For example, the buildfile applies to following command
// to the portfilter_test executable:
//
//	/usr/bin/sudo setcap "cap_bpf+ep cap_net_admin+ep cap_net_raw+ep" $@
func BpfSockFilter(port uint16) (int, error) {
	spec, err := loadPortfilter()
	if err != nil {
		return -1, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return -1, err
	}
	// We only need the collection to initialize stuff.
	defer coll.Close()

	// We keep the program, so the collection can be closed without closing the program.
	prog := coll.DetachProgram("bpf_port_filter")
	if prog == nil {
		panic("no program named pbf_port_filter found")
	}

	// Now load the map and populate it with our port mapping. We let the fd be closed along with
	// the collection: we are done with it. The program keeps the map alive.
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

	return prog.FD(), nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
