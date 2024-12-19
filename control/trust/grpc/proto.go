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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
)

func requestToChainQuery(req *cppb.ChainsRequest) (trust.ChainQuery, error) {
	var validity cppki.Validity
	if req.AtLeastValidUntil != nil {
		if err := req.AtLeastValidUntil.CheckValid(); err != nil {
			return trust.ChainQuery{}, serrors.Wrap("validating at_least_valid_until", err)
		}
		validity.NotAfter = req.AtLeastValidUntil.AsTime()

		// If AtLeastValidUntil is set but AtLeastValidSince is not this request
		// comes from a legacy client that does not support the new protobuf. In
		// this case we set AtLeastValidSince to AtLeastValidUntil to get the
		// same behavior as before.
		if req.AtLeastValidSince == nil {
			validity.NotBefore = validity.NotAfter
		}
	}
	if req.AtLeastValidSince != nil {
		if err := req.AtLeastValidSince.CheckValid(); err != nil {
			return trust.ChainQuery{}, serrors.Wrap("validating at_least_valid_since", err)
		}
		validity.NotBefore = req.AtLeastValidSince.AsTime()
	}

	return trust.ChainQuery{
		IA:           addr.IA(req.IsdAs),
		SubjectKeyID: req.SubjectKeyId,
		Validity:     validity,
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
	// If the query is for the latest version don't validate the ID fully, only
	// the ISD ID.
	if id.Base.IsLatest() && id.Serial.IsLatest() {
		if id.ISD == 0 {
			return cppki.TRCID{}, cppki.ErrWildcardISD
		}
		return id, nil
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
		Trc: trc.Raw, // nolint - name from protobuf
	}
}
