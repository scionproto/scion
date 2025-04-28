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

package afpacketudpip

import (
	"encoding/binary"
	"fmt"

	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func RawSocket(ifIndex int, port uint16) (int, error) {
	const SO_ATTACH_BPF = 50

	sock, err := openRawSock(ifIndex)
	if err != nil {
		return -1, err
	}
	// FIXME: Shouldn't close on return.
	defer syscall.Close(sock)

	// Now load our BPF por filter program.
	spec, err := loadPortfilter()
	if err != nil {
		fmt.Printf("loadPortFiler failed\n")
		return -1, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Printf("NewCollection failed\n")
		return -1, err
	}
	// FIXME: Shouldn't close on return.
	defer coll.Close()
	prog := coll.DetachProgram("bpf_port_filter")
	if prog == nil {
		panic("no program named pbf_port_verdict found")
	}
	// FIXME: Shouldn't close on return.
	defer prog.Close()

	// Now load the map and populate it with our port mapping.
	myMap := coll.DetachMap("sock_map_flt")
	if myMap == nil {
		panic(fmt.Errorf("no map named sock_map_rx found"))
	}
	// map.Put plays crystal ball with key and value so it accepts either
	// pointers or values. The kernel expects addresses in all cases.
	idx := uint32(0)
	portNbo := htons(port)
	if err := myMap.Put(idx, portNbo); err != nil {
		panic(fmt.Sprintf("error: %v, key=%p, val=%p\n", err, &idx, &portNbo))
	}
	// FIXME: Shouldn't close on return.
	defer myMap.Close()

	// Finally attach the program to the raw socket.
	err = unix.SetsockoptInt(int(sock), unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD())
	if err != nil {
		return -1, err
	}
	fmt.Printf("Filtering on eth index: %d and port: %d\n", ifIndex, port)
	return sock, nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func openRawSock(index int) (int, error) {
	// const ETH_P_ALL uint16 = 0x00<<8 | 0x03
	const ETH_P_ALL uint16 = 0x03

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = htons(ETH_P_ALL)
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

// func main() {
// 	name := flag.String("name", "ens32", "specify ethernet name")
// 	flag.Parse()
// 	if len(flag.Args()) > 0 || name == nil {
// 		flag.PrintDefaults()
// 		os.Exit(1)
// 	}
//
// 	Example_socketELF(*name)
//
// }
