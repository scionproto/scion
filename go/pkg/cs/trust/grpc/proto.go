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

package grpc

import (
	"crypto/x509"

	"github.com/golang/protobuf/ptypes"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
)

func requestToChainQuery(req *cppb.ChainsRequest) (trust.ChainQuery, error) {
	date, err := ptypes.Timestamp(req.Date)
	if err != nil {
		return trust.ChainQuery{}, err
	}
	return trust.ChainQuery{
		IA:           addr.IAInt(req.IsdAs).IA(),
		SubjectKeyID: req.SubjectKeyId,
		Date:         date,
	}, nil
}

func requestToTRCQuery(req *cppb.TRCRequest) (cppki.TRCID, error) {
	if req.Isd > uint32(addr.MaxISD) {
		return cppki.TRCID{}, serrors.New("requested ISD not in range",
			"max", addr.MaxISD, "isd", req.Isd)
	}
	id := cppki.TRCID{
		ISD:    addr.ISD(req.Isd),
		Base:   scrypto.Version(req.Base),
		Serial: scrypto.Version(req.Serial),
	}
	if err := id.Validate(); err != nil {
		return cppki.TRCID{}, err
	}
	return id, nil
}

func chainsToResponse(chains [][]*x509.Certificate) *cppb.ChainsResponse {
	rep := &cppb.ChainsResponse{
		Chains: make([]*cppb.Chain, 0, len(chains)),
	}
	for _, chain := range chains {
		rep.Chains = append(rep.Chains, &cppb.Chain{
			AsCert: chain[0].Raw,
			CaCert: chain[1].Raw,
		})
	}
	return rep
}

func trcToResponse(trc cppki.SignedTRC) *cppb.TRCResponse {
	return &cppb.TRCResponse{
		Trc: trc.Raw,
	}
}
