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

package messenger

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/snet/rpt"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
)

// TestCase data
var (
	mockTRC = &cert_mgmt.TRC{RawTRC: common.RawBytes("foobar")}
)

func MockTRCHandler(request *infra.Request) {
	messengerI, ok := infra.MessengerFromContext(request.Context())
	if !ok {
		log.Warn("Unable to service request, no Messenger interface found")
		return
	}
	messenger, ok := messengerI.(*Messenger)
	if !ok {
		log.Warn("Unable to service request, bad Messenger value found")
		return
	}
	subCtx, cancelF := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancelF()
	if err := messenger.SendTRC(subCtx, mockTRC, &MockAddress{}, request.ID); err != nil {
		log.Error("Server error", "err", err)
	}
}

func TestTRCExchange(t *testing.T) {
	Convey("Setup", t, func() {
		c2s, s2c := p2p.New()
		clientMessenger := setupMessenger(c2s, "client")
		serverMessenger := setupMessenger(s2c, "server")

		Convey("Client/server", xtest.Parallel(func(sc *xtest.SC) {
			// The client sends a TRC request to the server, and receives the
			// TRC.
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()

			msg := &cert_mgmt.TRCReq{ISD: 42, Version: 1337, CacheOnly: true}
			trc, err := clientMessenger.GetTRC(ctx, msg, &MockAddress{}, 1337)
			// CloseServer now, to guarantee it is run even if an assertion
			// fails and execution of the client stops
			serverMessenger.CloseServer()
			sc.SoMsg("client request err", err, ShouldBeNil)
			sc.SoMsg("client received trc", trc, ShouldResemble, mockTRC)
		}, func(sc *xtest.SC) {
			// The server receives a TRC request from the client, passes it to
			// the mock TRCRequest handler which sends back the result.
			serverMessenger.AddHandler(TRCRequest, infra.HandlerFunc(MockTRCHandler))
			serverMessenger.ListenAndServe()
		}))
	})
}

func setupMessenger(conn net.PacketConn, name string) *Messenger {
	transport := rpt.New(conn, log.New("name", name))
	dispatcher := disp.New(transport, DefaultAdapter, log.New("name", name))
	return New(dispatcher, nil, log.Root().New("name", name))
}

func TestMain(m *testing.M) {
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
