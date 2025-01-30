// Copyright 2024 SCION Association
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

package main

import (
	"reflect"
	"unsafe"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/sys/unix"
)

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
	// as the Go run-time has no idea that this is a blocking write. This is perfectly fine for our
	// use case.
	n, _, err := unix.Syscall6(unix.SYS_SENDMMSG,
		uintptr(sender.fd),
		uintptr(unsafe.Pointer(&sender.msgs[0])),
		uintptr(len(sender.msgs)),
		0, 0, 0)
	if err == 0 {
		return int(n), nil
	}
	return int(n), err
}
