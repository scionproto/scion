// Copyright 2025 SCION Association
//
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gopacket/gopacket/afpacket"
)

// For any of the below to work, the calling process must have the following capabilities:
// cap_bpf, cap_net_admin, cap_net_raw. For example, the buildfile applies to following command
// to the portfilter_test executable:
//
//	/usr/bin/sudo setcap "cap_bpf+ep cap_net_admin+ep cap_net_raw+ep" executable_file

// KFilterHandle holds the interface->kernel filter and keeps it alive until Closed. Link refers to
// the traffic control filter for the kernel stack. As long as such an object exists, the filter
// remain active. kObjs refers to the filter resources; that is the program and its map.
type KFilterHandle struct {
	kLink link.Link
	kObjs *ebpf.Collection
}

// Close causes the filter to go away.
func (kf *KFilterHandle) Close() {
	kf.kLink.Close()
	kf.kObjs.Close()
}

// Adds the given port to the map of the given filter. As a result UDP/IP packets destined to that
// port will be filtered out from the kernel networking stack.
func (kf *KFilterHandle) AddAddrPort(addrPort netip.AddrPort) {
	myMap := kf.kObjs.Maps["k_map_flt"]
	if myMap == nil {
		panic(fmt.Errorf("no map named k_map_flt found"))
	}

	// map.Put plays crystal ball with key and value so it accepts either
	// pointers or values.
	var key [20]byte
	addr := addrPort.Addr()
	if addr.Is4() || addr.Is4In6() {
		addrBytes := addr.As4()
		copy(key[0:4], addrBytes[0:4])
		key[18] = byte(4)
	} else {
		addrBytes := addr.As16()
		copy(key[0:16], addrBytes[0:16])
		key[18] = byte(6)
	}
	binary.BigEndian.PutUint16(key[16:18], addrPort.Port())
	b := uint8(0)
	if err := myMap.Put(key, b); err != nil {
		panic(fmt.Sprintf("error kFilter AddPort: %v, key=%p\n", err, &key))
	}
}

// BpfKFilter attaches a SCHED_CLS program to the network interface "ifIndex". The SCHED_CLS program
// filters all traffic to specified ports from interface "ifIndex" out of the kernel networking
// stack.
//
// Specifically, all traffic is delivered to the kernel networking stack, except UDP/IP to a port
// that has been added to the map.
//
// Note that every call to this function results in attaching a new filter to the interface. The
// filters operate serially.
//
// To insert ports into the filter's map, use the AddPort method.
//
// Returns: a handle referring to the program and map. Calling the handle's Close() method will
// discard both.
func BpfKFilter(ifIndex int) (*KFilterHandle, error) {
	spec, err := loadKfilter()
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}

	// We keep the program.
	prog := coll.Programs["bpf_k_filter"]
	if prog == nil {
		panic("no program named bpf_k_filter found")
	}

	// Attach the program to the interface. We attach it at head; it has almost zero cost.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifIndex,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Head(),
	})
	if err != nil {
		prog.Close()
		coll.Close()
		return nil, err
	}

	kf := &KFilterHandle{kLink: l, kObjs: coll}
	return kf, nil
}

// SFilterHandle holds the socket->application filter and keeps it alive until Closed. sObjs is the
// SockFilter rsources; that is, the program and its map. As long as such an object exists, the
// filter remains active.
type SFilterHandle struct {
	sObjs *ebpf.Collection
}

// Close causes the filter to go away.
func (sf *SFilterHandle) Close() {
	sf.sObjs.Close()
}

// Adds the given port to the map of the given filter. As a result UDP/IP packets destined to that
// port will be delivered to the associated socket.
func (sf *SFilterHandle) AddAddrPort(addrPort netip.AddrPort) {
	// Now load the map and populate it with our port mapping.
	myMap := sf.sObjs.Maps["sock_map_flt"]
	if myMap == nil {
		panic(fmt.Errorf("no map named sock_map_flt found"))
	}

	// map.Put plays crystal ball with key and value so it accepts either
	// pointers or values.
	var key [20]byte
	addr := addrPort.Addr()
	if addr.Is4() || addr.Is4In6() {
		addrBytes := addr.As4()
		copy(key[0:4], addrBytes[0:4])
		key[18] = byte(4)
	} else {
		addrBytes := addr.As16()
		copy(key[0:16], addrBytes[0:16])
		key[18] = byte(6)
	}
	binary.BigEndian.PutUint16(key[16:18], addrPort.Port())
	b := uint8(0)
	if err := myMap.Put(key, b); err != nil {
		panic(fmt.Sprintf("error sFilter AddPort: %v, key=%p\n", err, &key))
	}
}

// BpfSockFilter attaches a SOCK_FILTER program to the raw socket "afp".  The SOCK_FILTER program
// only allows traffic to specified ports to reach the socket referred to by "afp". Only the
// following traffic is delivered to the socket:
//
// UDP/IP: only if the destination port has been added to the map.
// ARP: all
// ICMPv6: all
//
// Note this function replaces any SOCK_FILTER already attached to the socket. There can be only
// one. To insert ports into the filter's map, use the AddPort method.
//
// Returns: a handle referring to the program and map. Calling the handle's Close() method will
// discard both.
func BpfSFilter(afp *afpacket.TPacket) (*SFilterHandle, error) {
	spec, err := loadSockfilter()
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}

	// We keep the program, so the collection can be closed without closing the program.
	prog := coll.Programs["bpf_sock_filter"]
	if prog == nil {
		panic("no program named pbf_sock_filter found")
	}

	err = afp.SetEBPF(int32(prog.FD()))
	if err != nil {
		prog.Close()
		coll.Close()
		return nil, err
	}

	sf := &SFilterHandle{sObjs: coll}
	return sf, nil
}

// LoadSockfilterSpec returns the eBPF collection spec for the sockfilter XDP program.
// This is used by AF_XDP to load the XDP program and attach it to a network interface.
func LoadSockfilterSpec() (*ebpf.CollectionSpec, error) {
	return loadSockfilter()
}
