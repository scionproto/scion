// Copyright 2018 ETH Zurich, Anapaya Systems
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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
)

// TestCase data
var (
	mockTRC = &cert_mgmt.TRC{RawTRC: common.RawBytes("foobar")}
)

func MockTRCHandler(request *infra.Request) *infra.HandlerResult {
	rw, ok := infra.ResponseWriterFromContext(request.Context())
	if !ok {
		log.Warn("Unable to service request, no resopnse writer found")
		return infra.MetricsErrInternal
	}
	subCtx, cancelF := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancelF()
	if err := rw.SendTRCReply(subCtx, mockTRC); err != nil {
		log.Error("Server error", "err", err)
		return infra.MetricsErrInternal
	}
	return infra.MetricsResultOk
}

func TestTRCExchange(t *testing.T) {
	Convey("Setup", t, func() {
		c2s, s2c := p2p.NewPacketConns()
		clientMessenger := setupMessenger(xtest.MustParseIA("1-ff00:0:1"), c2s, "client")
		serverMessenger := setupMessenger(xtest.MustParseIA("2-ff00:0:1"), s2c, "server")

		Convey("Client/server", xtest.Parallel(func(sc *xtest.SC) {
			// The client sends a TRC request to the server, and receives the
			// TRC.
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()

			msg := &cert_mgmt.TRCReq{ISD: 42, Version: 1337, CacheOnly: true}
			trc, err := clientMessenger.GetTRC(ctx, msg, nil, 1337)
			// CloseServer now, to guarantee it is run even if an assertion
			// fails and execution of the client stops
			serverMessenger.CloseServer()
			sc.SoMsg("client request err", err, ShouldBeNil)
			sc.SoMsg("client received trc", trc, ShouldResemble, mockTRC)
		}, func(sc *xtest.SC) {
			// The server receives a TRC request from the client, passes it to
			// the mock TRCRequest handler which sends back the result.
			serverMessenger.AddHandler(infra.TRCRequest, infra.HandlerFunc(MockTRCHandler))
			serverMessenger.ListenAndServe()
		}))
	})
}

func setupMessenger(ia addr.IA, conn net.PacketConn, name string) *Messenger {
	config := &Config{
		IA:                           ia,
		DisableSignatureVerification: true,
		Dispatcher: disp.New(
			transport.NewPacketTransport(conn),
			DefaultAdapter,
			log.New("name", name),
		),
		Logger: log.Root().New("name", name),
	}
	return New(config)
}

func TestMain(m *testing.M) {
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
