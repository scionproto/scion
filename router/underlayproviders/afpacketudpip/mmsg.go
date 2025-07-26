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

//go:build linux

package afpacketudpip

import (
	"reflect"
	"runtime"
	"unsafe"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/pkg/log"
)

// TODO(jiceatscion): there is another copy of this code in router_benchmark. Move this to a common
// package (in underlay for example) or, probably better, specialize this one to make it more
// efficient for the router's use.

type mmsgHdr struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte
}

// mpktSender is a helper class to add the ability of using the sendmmsg system call
// with afpacket sockets.
type mpktSender struct {
	fd     int
	tp     *afpacket.TPacket
	msgs   []mmsgHdr
	iovecs []unix.Iovec
}

func newMpktSender(tp *afpacket.TPacket) *mpktSender {
	sender := &mpktSender{}

	// Unceremonious but necessary until we submit a change (which would have to be more general
	// than this) to the afpacket project and get it merged.
	fdv := reflect.ValueOf(tp).Elem().FieldByName("fd")
	sender.fd = int(fdv.Int())
	// This is to make sure that tp cannot be finalized before we're done abusing its file desc.
	sender.tp = tp

	// Try and bypass queing discipline. If that doesn't work, we'll survive.
	err := unix.SetsockoptInt(sender.fd, unix.SOL_PACKET, unix.PACKET_QDISC_BYPASS, 1)
	if err != nil {
		log.Info("Could not bypass queing discipline", "err", err)
	}

	// If we're going to send, we need to make sure we're not receiving our own stuff. The default
	// behaviour is less than clear. The loopback doesn't work with veth, but likely does with
	// everything else.
	err = unix.SetsockoptInt(sender.fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)
	if err != nil {
		panic(err)
	}
	return sender
}

func (sender *mpktSender) setPkts(ps [][]byte) {
	numP := len(ps)
	sender.msgs = make([]mmsgHdr, numP)
	sender.iovecs = make([]unix.Iovec, numP)

	for i, p := range ps {
		if len(p) > 0 {
			sender.iovecs[i].Base = (*byte)(unsafe.Pointer(&p[0]))
			sender.iovecs[i].SetLen(len(p))
		}
		sender.msgs[i].hdr.Iov = &sender.iovecs[i]
		sender.msgs[i].hdr.Iovlen = 1
	}
}

func (sender *mpktSender) sendAll() (int, error) {
	// This will hog a core (as far as the Go scheduler is concerned) for the duration of the call
	// as the Go run-time has no idea that this may be a ~blocking write. This is perfectly fine for
	// our use case.
	for {
		n, _, err := unix.Syscall6(unix.SYS_SENDMMSG,
			uintptr(sender.fd),
			uintptr(unsafe.Pointer(&sender.msgs[0])),
			uintptr(len(sender.msgs)),
			uintptr(unix.MSG_DONTWAIT), // return when the interface queue is full.
			0, 0)
		if err == 0 {
			// we sent some packets.
			return int(n), nil
		}
		if err == unix.EWOULDBLOCK {
			// We sent nothing at all. The queue is completely full. Take a breather (cheaper than
			// using poll or select).
			runtime.Gosched()
			continue
		}
		// Some error other than EWOULDBLOCK. Nothing was sent either
		return 0, err
	}
}
