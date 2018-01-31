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

package trust

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/proto"
)

var (
	testISDList = []uint16{1, 2}
	testASList  = []addr.ISD_AS{
		{I: 1, A: 11}, {I: 1, A: 12}, {I: 1, A: 13}, {I: 1, A: 16}, {I: 1, A: 19},
		{I: 2, A: 21}, {I: 2, A: 22}, {I: 2, A: 23}, {I: 2, A: 25},
	}
	trcObjects   map[uint16]*trc.TRC
	chainObjects map[addr.ISD_AS]*cert.Chain
)

type FakeMessenger struct{}

func NewFakeMessenger() infra.Messenger {
	return &FakeMessenger{}
}

func (m *FakeMessenger) RecvMsg(ctx context.Context) (proto.Cerealizable, net.Addr, error) {
	panic("not implemented")
}

func (m *FakeMessenger) GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq,
	a net.Addr) (*cert_mgmt.TRC, error) {
	trcObj, ok := trcObjects[msg.ISD]
	if !ok {
		return nil, common.NewBasicError("TRC not found", nil)
	}

	compressedTRC, err := trcObj.Compress()
	if err != nil {
		return nil, common.NewBasicError("Unable to compress TRC", nil)
	}
	return &cert_mgmt.TRC{RawTRC: compressedTRC}, nil
}

func (m *FakeMessenger) SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr) error {
	panic("not implemented")
}

func (m *FakeMessenger) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq,
	a net.Addr) (*cert_mgmt.Chain, error) {
	chain, ok := chainObjects[*msg.IA()]
	if !ok {
		return nil, common.NewBasicError("Chain not found", nil)
	}

	compressedChain, err := chain.Compress()
	if err != nil {
		return nil, common.NewBasicError("Unable to compress Chain", nil)
	}
	return &cert_mgmt.Chain{RawChain: compressedChain}, nil
}

func (m *FakeMessenger) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr) error {
	panic("not implemented")
}

func (m *FakeMessenger) AddHandler(msgType string, h infra.Handler) {
	panic("not implemented")
}

func (m *FakeMessenger) ListenAndServe() {
	panic("not implemented")
}

func (m *FakeMessenger) CloseServer() error {
	panic("not implemented")
}

type FakeAddress struct{}

func (f *FakeAddress) Network() string {
	panic("not implemented")
}

func (f *FakeAddress) String() string {
	return ""
}

func TestTrustTrails(t *testing.T) {
	Convey("", t, func() {
		db, err := trustdb.New(randomFileName())
		SoMsg("trustdb init error", err, ShouldBeNil)
		store, err := NewStore(db, addr.ISD_AS{I: 1, A: 1}, log.Root())
		// Add trust root for this trust store manually
		err = store.trustdb.InsertTRCCtx(context.Background(), 2, 0, trcObjects[2])
		SoMsg("root insertion err", err, ShouldBeNil)

		// Enable fake network access for trust database
		messenger := NewFakeMessenger()
		store.StartResolvers(messenger, false)

		Convey("Validate using trail from ISD2 to AS1-16", func() {
			// Test that 1-16 Certificate can be validate
			trail := []Descriptor{
				{
					Version: 0,
					IA:      addr.ISD_AS{I: 1, A: 16},
					Type:    ChainDescriptor,
				},
				{
					Version: 0,
					IA:      addr.ISD_AS{I: 1, A: 0},
					Type:    TRCDescriptor,
				},
				{
					Version: 0,
					IA:      addr.ISD_AS{I: 2, A: 0},
					Type:    TRCDescriptor,
				},
			}
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			cert, err := store.GetCertificate(ctx, trail, &FakeAddress{})
			cancelF()
			SoMsg("fetch err", err, ShouldBeNil)
			SoMsg("cert", cert, ShouldResemble, chainObjects[addr.ISD_AS{I: 1, A: 16}].Leaf)
		})

		Convey("Fail to validate incomplete trail from ISD2 to AS1-19", func() {
			// Test that 1-19 can't be validated due to incomplete trail
			trail := []Descriptor{
				{
					Version: 0,
					IA:      addr.ISD_AS{I: 1, A: 19},
					Type:    ChainDescriptor,
				},
				{
					Version: 0,
					IA:      addr.ISD_AS{I: 2, A: 0},
					Type:    TRCDescriptor,
				},
			}
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			cert, err := store.GetCertificate(ctx, trail, &FakeAddress{})
			cancelF()
			SoMsg("fetch err", err, ShouldNotBeNil)
			SoMsg("cert", cert, ShouldBeNil)
		})
	})
}

func randomFileName() string {
	file, err := ioutil.TempFile("", "db-test-")
	if err != nil {
		panic("unable to create temp file")
	}
	name := file.Name()
	err = file.Close()
	if err != nil {
		panic("unable to close temp file")
	}
	return name
}

func TestMain(m *testing.M) {
	log.Root().SetHandler(log.DiscardHandler())
	trcObjects = make(map[uint16]*trc.TRC)
	for _, isd := range testISDList {
		trcObj, err := trc.TRCFromFile(getTRCFileName(isd, 0), false)
		if err != nil {
			fatal(err)
		}
		trcObjects[isd] = trcObj
	}
	chainObjects = make(map[addr.ISD_AS]*cert.Chain)
	for _, ia := range testASList {
		chain, err := cert.ChainFromFile(getChainFileName(ia, 0), false)
		if err != nil {
			fatal(err)
		}
		chainObjects[ia] = chain
	}
	os.Exit(m.Run())
}

func getTRCFileName(isd uint16, version uint64) string {
	return fmt.Sprintf("testdata/ISD%d-V%d.trc", isd, version)
}

func getChainFileName(ia addr.ISD_AS, version uint64) string {
	return fmt.Sprintf("testdata/ISD%d-AS%d-V%d.crt", ia.I, ia.A, version)
}

func fatal(err error) {
	log.Error("Fatal error", "err", common.FmtError(err))
	os.Exit(1)
}
