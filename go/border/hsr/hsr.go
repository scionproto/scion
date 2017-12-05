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

// Package hsr (High Speed Router) implements Go bindings for libhsr using CGO.
// libhsr uses the concept of 'ports', which is a combination of interface and
// address+udp port. The interface is either a hardware interface via DPDK, or
// a virtual interface using libpcap.
package hsr

/*
#cgo CFLAGS: -I../../../c/lib
#cgo LDFLAGS: -lhsr -ldpdk -lmnl -lzlog -lscion
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <zlog.h>
#include "hsr/hsr_interface.h"

typedef struct sockaddr_in saddr_in;
typedef struct sockaddr_in6 saddr_in6;
typedef struct sockaddr_storage saddr_storage;
*/
import "C"

import (
	"flag"
	"unsafe"

	//log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/border/metrics"
	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/topology"
)

var hsrInMin = flag.Int("hsr.in.min_pkts", 20, "Minimum packets to read per loop")
var hsrInTout = flag.Int("hsr.in.tout", 10,
	"Maximum time (in us) to wait for packets. -1 means no timeout.")

// MaxPkts determines how many packets can be read in a single call to libhsr's get_packets.
const MaxPkts = 32

// AddrMeta contains address metadata for a specific libhsr port. This is
// attached to packets that are sent from/to the specified address, to allow
// processing. In particular, it contains the address in both Go and C formats.
type AddrMeta struct {
	// GoAddr is a Go version of the address.
	GoAddr *topology.AddrInfo
	// CAddr is a C version of the address.
	CAddr C.saddr_storage
	// DirFrom is the direction a packet was received from.
	DirFrom rcmn.Dir
	// IfIDs is a list of matching interface IDs. Local (i.e. facing the local
	// AS) addresses can have multiple interfaces associated with them.
	IfIDs []common.IFIDType
	// Labels is a set of prometheus labels to apply to packets using this port.
	Labels prometheus.Labels
}

// Slice of AddrMetas, indexed by the libhsr port ID.
var AddrMs []AddrMeta

// Init initialises libhsr, and relevant metadata.
func Init(zlog_cfg string, args []string, addrMs []AddrMeta) error {
	defer liblog.LogPanicAndExit()
	// Create a C-style argv to pass to router_init.
	argv := make([]*C.char, 0, len(args))
	for _, arg := range args {
		argv = append(argv, C.CString(arg))
	}
	// Initialise libhsr. Its logging is controlled by the zlog config and
	// category, and DPDK's general options are configured by the argv.
	if C.router_init(C.CString(zlog_cfg), C.CString("border"), C.int(len(argv)), &argv[0]) != 0 {
		return common.NewCError("Failure initialising libhsr (router_init)")
	}
	AddrMs = addrMs
	// Calculate the C address structure from the Go address structure.
	cAddrs := make([]C.saddr_storage, len(AddrMs))
	for i := range AddrMs {
		taiToSaddr(AddrMs[i].GoAddr, &AddrMs[i].CAddr)
		cAddrs[i] = AddrMs[i].CAddr
	}
	// Configure network ports
	if C.setup_network(&cAddrs[0], C.int(len(cAddrs))) != 0 {
		return common.NewCError("Failure initialising libhsr (setup_network)")
	}
	// Create the libhsr worker threads.
	if C.create_lib_threads() != 0 {
		return common.NewCError("Failure initialising libhsr (create_lib_threads)")
	}
	return nil
}

// Finish handles cleanup, and should be called when shutting down.
func Finish() {
	// Flush libhsr's logging.
	C.zlog_fini()
}

// HSR manages packet input from libhsr.
type HSR struct {
	// InPkts is an array of C RouterPacket structs. The RouterPacket.buf
	// pointers are set to point to Go RtrPkt.Raw buffers, so libhsr is writing
	// directly into Go structs, avoiding a lot of copying overhead.
	InPkts [MaxPkts]C.RouterPacket
}

func NewHSR() *HSR {
	h := HSR{}
	// Allocate storage for each RouterPacket's src/dest fields.
	for i := range h.InPkts {
		h.InPkts[i].dst = &C.saddr_storage{}
		h.InPkts[i].src = &C.saddr_storage{}
	}
	return &h
}

// GetPackets fills in a slice of Go RtrPkt's via libhsr. The usedPorts
// arg is used to indicate which ports received packets in this call.
func (h *HSR) GetPackets(rps []*rpkt.RtrPkt, usedPorts []bool) (int, error) {
	if len(rps) > MaxPkts {
		return 0, common.NewCError("Too many packets requested", "max", MaxPkts, "actual", len(rps))
	}
	// Set the C buffer pointers to the Go buffer addresses.
	// XXX(kormat): N.B. this breaks one of the CGO safety rules
	// (https://golang.org/cmd/cgo/#hdr-Passing_pointers) which is designed to
	// stop C from keeping copies of pointers to Go memory, and using them
	// later. There is no way to comply with this rule without passing every
	// buffer into libhsr individually, which is bad for performance.  In our
	// case libhsr does not keep any pointers by design, so it is safe, but it
	// does require setting the GODEBUG environment variable to "cgocheck=0" to
	// stop Go's checks from terminating the program.
	for i, rp := range rps {
		h.InPkts[i].buf = (*C.uint8_t)(unsafe.Pointer(&rp.Raw[0]))
	}
	count := int(C.get_packets(&h.InPkts[0], C.int(*hsrInMin),
		C.int(len(rps)), C.int(*hsrInTout)))
	for i := 0; i < count; i++ {
		rp := rps[i]      // Go packet.
		cp := h.InPkts[i] // C packet.
		// Trim Go buffer to the length reported by libhsr.
		rp.Raw = rp.Raw[:int(cp.buflen)]
		// Convert the source address from C to Go.
		var err error
		if rp.Ingress.Src, err = saddrToTAI(cp.src); err != nil {
			return i, err
		}
		// Fill out packet metadata from AddrMs
		rp.Ingress.Dst = AddrMs[cp.port_id].GoAddr
		rp.Ingress.IfIDs = AddrMs[cp.port_id].IfIDs
		rp.DirFrom = AddrMs[cp.port_id].DirFrom
		// Indicate this port was used
		usedPorts[cp.port_id] = true
		// Update global packet/byte counters
		labels := AddrMs[cp.port_id].Labels
		metrics.InputPkts.With(labels).Inc()
		metrics.InputBytes.With(labels).Add(float64(len(rp.Raw)))
	}
	return count, nil
}

// SendPacket sends a single packet via libhsr.
func SendPacket(dst *topology.AddrInfo, portID int, buf common.RawBytes) error {
	var cp C.RouterPacket
	// Set C packet pointer to Go buffer.
	cp.buf = (*C.uint8_t)(unsafe.Pointer(&buf[0]))
	cp.buflen = C.size_t(len(buf))
	// Use pre-converted C source address from AddrMs.
	cp.src = &AddrMs[portID].CAddr
	// Convert destination address from Go to C.
	cp.dst = &C.saddr_storage{}
	taiToSaddr(dst, cp.dst)
	cp.port_id = C.uint8_t(portID)
	if C.send_packet(&cp) != 0 {
		return common.NewCError("Error sending packet through HSR")
	}
	return nil
}

// saddrToTAI converts C's sockaddr_storage type to Go's *topology.AddrInfo
func saddrToTAI(saddr *C.saddr_storage) (*topology.AddrInfo, error) {
	switch saddr.ss_family {
	case C.AF_INET:
		saddr := (*C.saddr_in)(unsafe.Pointer(saddr))
		return &topology.AddrInfo{
			Overlay: overlay.UDPIPv4,
			IP:      C.GoBytes(unsafe.Pointer(&saddr.sin_addr), 4),
		}, nil
	case C.AF_INET6:
		saddr := (*C.saddr_in6)(unsafe.Pointer(saddr))
		return &topology.AddrInfo{
			Overlay: overlay.UDPIPv4,
			IP:      C.GoBytes(unsafe.Pointer(&saddr.sin6_addr), 16),
		}, nil
	default:
		return nil, common.NewCError("Unsupported sockaddr family type", "type", saddr.ss_family)
	}
}

// taiToSaddr converts Go's *topology.AddrInfo type to C's sockaddr_storage type.
func taiToSaddr(tai *topology.AddrInfo, saddr *C.saddr_storage) {
	// Convert Go int to network-byte-order C int
	cport := C.in_port_t(C.htons(C.uint16_t(tai.L4Port)))
	if tai.IP.To4() != nil {
		s4 := (*C.saddr_in)(unsafe.Pointer(saddr))
		s4.sin_family = C.AF_INET
		s4.sin_port = cport
		copy((*[4]byte)(unsafe.Pointer(&s4.sin_addr))[:], tai.IP.To4())
	} else {
		s6 := (*C.saddr_in6)(unsafe.Pointer(saddr))
		s6.sin6_family = C.AF_INET6
		s6.sin6_port = cport
		copy((*[16]byte)(unsafe.Pointer(&s6.sin6_addr))[:], tai.IP)
	}
}
