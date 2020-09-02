// Copyright 2020 Anapaya Systems
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

package grpc_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
	trustgrpc "github.com/scionproto/scion/go/pkg/trust/grpc"
	trustmetrics "github.com/scionproto/scion/go/pkg/trust/internal/metrics"
)

func TestChainQueryToReq(t *testing.T) {
	query := trust.ChainQuery{
		IA:           xtest.MustParseIA("1-ff00:0:110"),
		Date:         time.Now().UTC().Truncate(time.Second),
		SubjectKeyID: []byte("frank"),
	}
	req := trustgrpc.ChainQueryToReq(query)
	assert.Equal(t, uint64(query.IA.IAInt()), req.IsdAs)
	assert.Equal(t, query.SubjectKeyID, req.SubjectKeyId)
	ts, err := ptypes.Timestamp(req.Date)
	assert.NoError(t, err)
	assert.Equal(t, query.Date, ts)
}

func TestIDToReq(t *testing.T) {
	id := cppki.TRCID{
		ISD:    1,
		Base:   2,
		Serial: 3,
	}
	req := trustgrpc.IDToReq(id)
	assert.Equal(t, uint32(1), req.Isd)
	assert.Equal(t, uint64(2), req.Base)
	assert.Equal(t, uint64(3), req.Serial)
}

func TestRepToChains(t *testing.T) {
	chain110 := xtest.LoadChain(t, "../testdata/common/certs/ISD1-ASff00_0_110.pem")
	chain112 := xtest.LoadChain(t, "../testdata/common/certs/ISD1-ASff00_0_112.pem")

	testCases := map[string]struct {
		Input          func() []*cppb.Chain
		ExpectedLabel  string
		ExpectedChains [][]*x509.Certificate
		Assertion      assert.ErrorAssertionFunc
	}{
		"normal": {
			Input: func() []*cppb.Chain {
				return []*cppb.Chain{
					{AsCert: chain110[0].Raw, CaCert: chain110[1].Raw},
					{AsCert: chain112[0].Raw, CaCert: chain112[1].Raw},
				}
			},
			ExpectedChains: [][]*x509.Certificate{chain110, chain112},
			Assertion:      assert.NoError,
		},
		"empty": {
			Input: func() []*cppb.Chain {
				return []*cppb.Chain{}
			},
			ExpectedChains: [][]*x509.Certificate{},
			Assertion:      assert.NoError,
		},
		"nil": {
			Input: func() []*cppb.Chain {
				return nil
			},
			ExpectedChains: [][]*x509.Certificate{},
			Assertion:      assert.NoError,
		},
		"garbage AS": {
			Input: func() []*cppb.Chain {
				return []*cppb.Chain{{
					AsCert: []byte("garbage"),
					CaCert: chain110[1].Raw,
				}}
			},
			ExpectedLabel: trustmetrics.ErrParse,
			Assertion:     assert.Error,
		},
		"garbage CA": {
			Input: func() []*cppb.Chain {
				return []*cppb.Chain{{
					AsCert: chain110[0].Raw,
					CaCert: []byte("garbage"),
				}}
			},
			ExpectedLabel: trustmetrics.ErrParse,
			Assertion:     assert.Error,
		},
		"invalid chain": {
			Input: func() []*cppb.Chain {
				return []*cppb.Chain{{
					AsCert: chain110[0].Raw,
					CaCert: chain110[0].Raw,
				}}
			},
			ExpectedLabel: trustmetrics.ErrValidate,
			Assertion:     assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			chains, label, err := trustgrpc.RepToChains(tc.Input())
			tc.Assertion(t, err)
			assert.Equal(t, tc.ExpectedChains, chains)
			assert.Equal(t, tc.ExpectedLabel, label)
		})
	}
}
