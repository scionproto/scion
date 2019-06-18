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

package snetproxy_test

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
)

var (
	Any = gomock.Any
)

var (
	localNoPortAddr = MustParseSnet("1-ff00:0:1,[192.168.0.1]:0")
	localAddr       = MustParseSnet("1-ff00:0:1,[192.168.0.1]:80")
	otherLocalAddr  = MustParseSnet("1-ff00:0:1,[192.168.0.1]:10080")
	bindAddr        = MustBuildOverlay("[192.168.0.2]:80")
	otherBindAddr   = MustBuildOverlay("[192.168.0.2]:10080")
	remoteAddr      = MustParseSnet("2-ff00:0:2,[172.16.0.1]:80")
	svc             = addr.SvcNone
	timeout         = time.Duration(0)
	testBuffer      = []byte{1, 2, 3}
)

var (
	dispatcherError            = &net.OpError{Err: os.NewSyscallError("write", syscall.ECONNRESET)}
	writeDispatcherError       = &net.OpError{Err: os.NewSyscallError("write", syscall.EPIPE)}
	writeNonDispatcherError    = common.NewBasicError("Misc error", nil)
	connectErrorFromDispatcher = common.NewBasicError("Port unavailable", nil)
)

func MustParseSnet(str string) *snet.Addr {
	address, err := snet.AddrFromString(str)
	if err != nil {
		panic(fmt.Sprintf("bad snet string %v, err=%v", str, err))
	}
	return address
}

func MustBuildOverlay(str string) *overlay.OverlayAddr {
	udpAddr, err := net.ResolveUDPAddr("udp4", str)
	if err != nil {
		panic(fmt.Sprintf("bad overlay address %v, err=%v", str, err))
	}
	ov, err := overlay.NewOverlayAddr(
		addr.HostFromIP(udpAddr.IP),
		addr.NewL4UDPInfo(uint16(udpAddr.Port)),
	)
	if err != nil {
		panic(fmt.Sprintf("cannot build overlay, err=%v", err))
	}
	return ov
}

// tickerMultiplier computes durations relative to the default reconnect
// ticking interval. This is needed for some timing tests that need sleep
// values to stay fairly close to the ticking interval.
func tickerMultiplier(multiplier time.Duration) time.Duration {
	return multiplier * snetproxy.DefaultTickerInterval
}

func TestMain(m *testing.M) {
	// Inject a smaller timeout s.t. tests run quickly
	snetproxy.DefaultTickerInterval = 10 * time.Millisecond
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
