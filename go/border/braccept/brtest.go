// Copyright 2018 ETH Zurich
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
	"fmt"
	"os"
	"time"

	"github.com/kormat/fmt15"
	"github.com/mattn/go-isatty"

	"github.com/scionproto/scion/go/border/braccept/tpkt"
)

// BRTest defines a single test
type BRTest struct {
	// Desc is a brief description of the test
	Desc string
	// Pre is the packet to be sent before the actual test packets.
	// An example of this packet would be an IFState to deactivate the interface when testing
	// for a revoked interface (OPTIONAL)
	Pre *tpkt.Pkt
	// In is the packet being sent to the border router
	In *tpkt.Pkt
	// Out is the list of expected packets. No expected packets means that the packet
	// should be dropped by the border router, and nothing is expected.
	Out []*tpkt.ExpPkt
	// Post is the packet to be sent to the border router once the test has been completed.
	// An example for this post packet would be an IFStateInfo to activate the interface and keep
	// the border router in a known state.
	Post *tpkt.Pkt
	// Ignore is the list of packets that should be ignored (OPTIONAL)
	Ignore []*tpkt.ExpPkt
	// Delay is the amount of time to wait after sending a packet. This is useful when sending
	// control packets to the BR in the Pre stage to allow for its processing (OPTIONAL)
	Delay time.Duration
	// Timeout is the time to wait for packets from the BR (OPTIONAL)
	Timeout time.Duration
}

func (t *BRTest) Summary(testPass bool) string {
	var result string
	if testPass {
		result = pass()
	} else {
		result = fail()
	}
	return fmt.Sprintf("Test %s: %s\n", t.Desc, result)
}

const (
	passUni = "\u2714"
	failUni = "\u2715"
	green   = 32
	red     = 31
)

func pass() string {
	if isatty.IsTerminal(os.Stdout.Fd()) {
		return fmt15.ColorStr(passUni, green)
	}
	return "PASS"
}

func fail() string {
	if isatty.IsTerminal(os.Stdout.Fd()) {
		return fmt15.ColorStr(failUni, red)
	}
	return "FAIL"
}
