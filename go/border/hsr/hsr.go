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

// +build hsr

package hsr

/*
#cgo CFLAGS: -I../../../lib
#cgo LDFLAGS: -lhsr -ldpdk -lmnl -lzlog -lscion
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <zlog.h>
#include "libhsr/hsr_interface.h"

typedef struct sockaddr_in saddr_in;
typedef struct sockaddr_in6 saddr_in6;
typedef struct sockaddr_storage saddr_storage;
*/
import "C"

import (
	"flag"
	"net"
	"unsafe"

	//log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/util"
)

var hsrInMin = flag.Int("hsr.in.min_pkts", 20, "Minimum packets to read per loop")
var hsrInTout = flag.Int("hsr.in.tout", 10,
	"Maximum time (in us) to wait for packets. -1 means no timeout.")

const MaxPkts = 32

type AddrMeta struct {
	GoAddr  *net.UDPAddr
	CAddr   C.saddr_storage
	DirFrom rpkt.Dir
	Labels  prometheus.Labels
}

var AddrMs []AddrMeta

func Init(conf string, args []string, addrMs []AddrMeta) *util.Error {
	defer liblog.PanicLog()
	argv := make([]*C.char, 0, len(args))
	for _, arg := range args {
		argv = append(argv, C.CString(arg))
	}
	if C.router_init(C.CString(conf), C.CString("border"), C.int(len(argv)), &argv[0]) != 0 {
		return util.NewError("Failure initialising libhsr (router_init)")
	}
	AddrMs = addrMs
	cAddrs := make([]C.saddr_storage, len(AddrMs))
	for i, addrM := range AddrMs {
		udpAddrToSaddr(addrM.GoAddr, &addrM.CAddr)
		cAddrs[i] = addrM.CAddr
	}
	if C.setup_network(&cAddrs[0], C.int(len(cAddrs))) != 0 {
		return util.NewError("Failure initialising libhsr (setup_network)")
	}
	if C.create_lib_threads() != 0 {
		return util.NewError("Failure initialising libhsr (create_lib_threads)")
	}
	return nil
}

func Finish() {
	C.zlog_fini()
}

type HSR struct {
	InPkts [MaxPkts]C.RouterPacket
}

func NewHSR() *HSR {
	h := HSR{}
	for i := range h.InPkts {
		h.InPkts[i].src = &C.saddr_storage{}
		h.InPkts[i].dst = &C.saddr_storage{}
	}
	return &h
}

func (h *HSR) GetPackets(rps []*rpkt.RPkt) ([]int, *util.Error) {
	if len(rps) > MaxPkts {
		return nil, util.NewError("Too many packets requested", "max", MaxPkts, "actual", len(rps))
	}
	for i, rp := range rps {
		h.InPkts[i].buf = (*C.uint8_t)(unsafe.Pointer(&rp.Raw[0]))
	}
	count := int(C.get_packets(unsafe.Pointer(&h.InPkts), C.int(*hsrInMin),
		C.int(len(rps)), C.int(*hsrInTout)))
	portIds := make([]int, count)
	for i := 0; i < count; i++ {
		rp := rps[i]
		r := h.InPkts[i]
		rp.Raw = rp.Raw[:int(r.buflen)]
		rp.Ingress.Src = &net.UDPAddr{}
		if err := saddrToUDPAddr(rp.Ingress.Src, r.src); err != nil {
			return nil, err
		}
		rp.Ingress.Dst = AddrMs[r.port_id].GoAddr
		rp.DirFrom = AddrMs[r.port_id].DirFrom
		portIds[i] = int(r.port_id)
	}
	return portIds, nil
}

func SendPacket(dst *net.UDPAddr, portID int, buf util.RawBytes) *util.Error {
	var rPkt C.RouterPacket
	rPkt.buf = (*C.uint8_t)(unsafe.Pointer(&buf[0]))
	rPkt.buflen = C.size_t(len(buf))
	rPkt.src = &AddrMs[portID].CAddr
	rPkt.dst = &C.saddr_storage{}
	udpAddrToSaddr(dst, rPkt.dst)
	rPkt.port_id = C.uint8_t(portID)
	if C.send_packet(&rPkt) != 0 {
		return util.NewError("Error sending packet through HSR")
	}
	return nil
}

func saddrToUDPAddr(addr *net.UDPAddr, saddr *C.saddr_storage) *util.Error {
	switch saddr.ss_family {
	case C.AF_INET:
		saddr := (*C.saddr_in)(unsafe.Pointer(saddr))
		addr.IP = C.GoBytes(unsafe.Pointer(&saddr.sin_addr), 4)
	case C.AF_INET6:
		saddr := (*C.saddr_in6)(unsafe.Pointer(saddr))
		addr.IP = C.GoBytes(unsafe.Pointer(&saddr.sin6_addr), 16)
	default:
		return util.NewError("Unsupported sockaddr family type", "type", saddr.ss_family)
	}
	return nil
}

func udpAddrToSaddr(addr *net.UDPAddr, saddr *C.saddr_storage) {
	if addr.IP.To4() != nil {
		s4 := (*C.saddr_in)(unsafe.Pointer(saddr))
		s4.sin_family = C.AF_INET
		s4.sin_port = C.in_port_t(C.htons(C.uint16_t(addr.Port)))
		copy((*[4]byte)(unsafe.Pointer(&s4.sin_addr))[:], addr.IP.To4())
	} else {
		s6 := (*C.saddr_in6)(unsafe.Pointer(saddr))
		s6.sin6_family = C.AF_INET6
		s6.sin6_port = C.in_port_t(C.htons(C.uint16_t(addr.Port)))
		copy((*[16]byte)(unsafe.Pointer(&s6.sin6_addr))[:], addr.IP)
	}
}
