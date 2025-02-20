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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	trustgrpc "github.com/scionproto/scion/control/trust/grpc"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

func TestReqToChainQuery(t *testing.T) {
	now := time.Now().UTC()
	validUntil := timestamppb.New(now)
	validSince := timestamppb.New(now.Add(-time.Hour))

	req := &cppb.ChainsRequest{
		IsdAs:             uint64(addr.MustParseIA("1-ff00:0:110")),
		SubjectKeyId:      []byte("tank"),
		AtLeastValidSince: validSince,
		AtLeastValidUntil: validUntil,
	}

	query, err := trustgrpc.RequestToChainQuery(req)
	require.NoError(t, err)
	assert.Equal(t, addr.IA(req.IsdAs), query.IA)
	assert.Equal(t, req.SubjectKeyId, query.SubjectKeyID)
	assert.Equal(t, now.Add(-time.Hour), query.Validity.NotBefore)
	assert.Equal(t, now, query.Validity.NotAfter)

	// Test with request from legacy client, i.e., AtLeastValidSince is nil.
	req.AtLeastValidSince = nil
	query, err = trustgrpc.RequestToChainQuery(req)
	require.NoError(t, err)
	assert.Equal(t, addr.IA(req.IsdAs), query.IA)
	assert.Equal(t, req.SubjectKeyId, query.SubjectKeyID)
	assert.Equal(t, now, query.Validity.NotBefore)
	assert.Equal(t, now, query.Validity.NotAfter)
}

func TestReqToTRCQuery(t *testing.T) {
	testCases := map[string]struct {
		Input     *cppb.TRCRequest
		Expected  cppki.TRCID
		Assertion assert.ErrorAssertionFunc
	}{
		"valid": {
			Input: &cppb.TRCRequest{
				Isd:    1,
				Base:   2,
				Serial: 3,
			},
			Expected: cppki.TRCID{
				ISD:    1,
				Base:   2,
				Serial: 3,
			},
			Assertion: assert.NoError,
		},
		"ISD too big": {
			Input: &cppb.TRCRequest{
				Isd:    uint32(addr.MaxISD) + 1,
				Base:   2,
				Serial: 3,
			},
			Assertion: assert.Error,
		},
		"ISD wildcard": {
			Input: &cppb.TRCRequest{
				Isd:    0,
				Base:   2,
				Serial: 3,
			},
			Assertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			id, err := trustgrpc.RequestToTRCQuery(tc.Input)
			tc.Assertion(t, err)
			assert.Equal(t, tc.Expected, id)
		})
	}
}

func TestChainsToRep(t *testing.T) {
	chain110 := []*x509.Certificate{{Raw: []byte("110-AS")}, {Raw: []byte("110-CA")}}
	chain120 := []*x509.Certificate{{Raw: []byte("120-AS")}, {Raw: []byte("120-CA")}}

	testCases := map[string]struct {
		Input    [][]*x509.Certificate
		Expected *cppb.ChainsResponse
	}{
		"normal": {
			Input: [][]*x509.Certificate{chain110, chain120},
			Expected: &cppb.ChainsResponse{
				Chains: []*cppb.Chain{
					{AsCert: chain110[0].Raw, CaCert: chain110[1].Raw},
					{AsCert: chain120[0].Raw, CaCert: chain120[1].Raw},
				},
			},
		},
		"empty": {
			Input: [][]*x509.Certificate{},
			Expected: &cppb.ChainsResponse{
				Chains: []*cppb.Chain{},
			},
		},
		"nil": {
			Input: nil,
			Expected: &cppb.ChainsResponse{
				Chains: []*cppb.Chain{},
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			chains := trustgrpc.ChainsToResponse(tc.Input)
			assert.Equal(t, tc.Expected, chains)
		})
	}
}

func TestTRCToRep(t *testing.T) {
	trc := cppki.SignedTRC{Raw: []byte("you can trust me, for sure!")}
	rep := trustgrpc.TRCToResponse(trc)
	assert.Equal(t, trc.Raw, rep.Trc) // nolint - name from published protobuf
}
