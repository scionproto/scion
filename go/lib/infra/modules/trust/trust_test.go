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
	"io/ioutil"
	"net"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
)

type FakeMessenger struct {
	rawTRC common.RawBytes
}

func NewFakeMessenger() (infra.Messenger, error) {
	raw, err := ioutil.ReadFile("testdata/ISD1-V0.trc")
	if err != nil {
		return nil, err
	}
	trcObject, err := trc.TRCFromRaw(raw, false)
	if err != nil {
		return nil, err
	}
	compressedRaw, err := trcObject.Compress()
	if err != nil {
		return nil, err
	}
	return &FakeMessenger{
		rawTRC: compressedRaw,
	}, nil
}

func (m *FakeMessenger) RecvMsg(ctx context.Context) (interface{}, net.Addr, error) {
	panic("not implemented")
}

func (m *FakeMessenger) GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq,
	a net.Addr) (*cert_mgmt.TRC, error) {
	return &cert_mgmt.TRC{RawTRC: m.rawTRC}, nil
}

func (m *FakeMessenger) SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr) error {
	panic("not implemented")
}

func (m *FakeMessenger) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq,
	a net.Addr) (*cert_mgmt.Chain, error) {
	panic("not implemented")
}

func (m *FakeMessenger) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr) error {
	panic("not implemented")
}

func (m *FakeMessenger) SendSignedCtrlPld() error {
	panic("not implemented")
}

func TestTrust(t *testing.T) {
	Convey("Create a new trust store", t, func() {
		messenger, err := NewFakeMessenger()
		SoMsg("messenger err", err, ShouldBeNil)
		store, err := NewStore(randomFileName(), log.Root())
		SoMsg("store err", err, ShouldBeNil)
		store.StartResolvers(messenger)
		Convey("Send request and get answer", func() {
			isd, version := uint16(1), uint64(5)
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			trc, err := store.GetTRC(ctx, isd, version)
			cancelF()
			SoMsg("err", err, ShouldBeNil)
			SoMsg("trc", trc, ShouldNotBeNil)
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
