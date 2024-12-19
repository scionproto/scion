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

	timestamppb "github.com/golang/protobuf/ptypes/timestamp"

	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
	trustmetrics "github.com/scionproto/scion/private/trust/internal/metrics"
)

func chainQueryToReq(query trust.ChainQuery) *cppb.ChainsRequest {
	return &cppb.ChainsRequest{
		IsdAs:             uint64(query.IA),
		SubjectKeyId:      query.SubjectKeyID,
		AtLeastValidSince: &timestamppb.Timestamp{Seconds: query.Validity.NotBefore.UTC().Unix()},
		AtLeastValidUntil: &timestamppb.Timestamp{Seconds: query.Validity.NotAfter.UTC().Unix()},
	}
}

func repToChains(pbChains []*cppb.Chain) ([][]*x509.Certificate, string, error) {
	chains := make([][]*x509.Certificate, 0, len(pbChains))
	for _, c := range pbChains {
		var err error
		chain := make([]*x509.Certificate, 2)
		if chain[0], err = x509.ParseCertificate(c.AsCert); err != nil {
			return nil, trustmetrics.ErrParse, serrors.Wrap("parsing AS certificate", err)
		}
		if chain[1], err = x509.ParseCertificate(c.CaCert); err != nil {
			return nil, trustmetrics.ErrParse, serrors.Wrap("parsing CA certificate", err)
		}
		if err := cppki.ValidateChain(chain); err != nil {
			return nil, trustmetrics.ErrValidate, err
		}
		chains = append(chains, chain)
	}
	return chains, "", nil
}

func idToReq(id cppki.TRCID) *cppb.TRCRequest {
	return &cppb.TRCRequest{
		Isd:    uint32(id.ISD),
		Base:   uint64(id.Base),
		Serial: uint64(id.Serial),
	}
}
