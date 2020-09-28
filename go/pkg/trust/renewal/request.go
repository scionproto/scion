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

package renewal

import (
	"context"
	"crypto/x509"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
)

// NewChainRenewalRequest builds a ChainRenewalRequest given a serialized CSR
// and a signer.
func NewChainRenewalRequest(ctx context.Context, csr []byte,
	signer trust.Signer) (*cppb.ChainRenewalRequest, error) {

	body := &cppb.ChainRenewalRequestBody{
		Csr: csr,
	}
	rawBody, err := proto.Marshal(body)
	if err != nil {
		return nil, err
	}
	signedMsg, err := signer.Sign(ctx, rawBody)
	if err != nil {
		return nil, err
	}
	return &cppb.ChainRenewalRequest{
		SignedRequest: signedMsg,
	}, nil
}

// VerifyChainRenewalRequest verifies the renewal request. It checks that the
// contained CSR is valid and correctly self-signed, and that the signature is
// valid and can be verified by a chain in the given chains.
func VerifyChainRenewalRequest(request *cppb.ChainRenewalRequest,
	chains [][]*x509.Certificate) (*x509.CertificateRequest, error) {

	if request == nil {
		return nil, serrors.New("request must not be nil")
	}
	var authChain []*x509.Certificate
	var msg *signed.Message
	for _, chain := range chains {
		m, err := signed.Verify(request.SignedRequest, chain[0].PublicKey)
		if err == nil {
			msg, authChain = m, chain
			break
		}
	}
	if msg == nil {
		return nil, serrors.New("no provided chain can verify the signature")
	}
	var body cppb.ChainRenewalRequestBody
	if err := proto.Unmarshal(msg.Body, &body); err != nil {
		return nil, serrors.WrapStr("parsing request body", err)
	}
	csr, err := x509.ParseCertificateRequest(body.Csr)
	if err != nil {
		return nil, serrors.WrapStr("parsing CSR", err)
	}
	csrIA, err := cppki.ExtractIA(csr.Subject)
	if err != nil {
		return nil, serrors.WrapStr("extracting ISD-AS from CSR", err)
	}
	if csrIA == nil {
		return nil, serrors.New("subject without ISD-AS", "subject", csr.Subject)
	}
	chainIA, err := cppki.ExtractIA(authChain[0].Subject)
	if err != nil {
		return nil, serrors.WrapStr("extracting ISD-AS from certificate chain", err)
	}
	if chainIA == nil {
		return nil, serrors.New("subject without ISD-AS", "subject", csr.Subject)
	}
	if !csrIA.Equal(*chainIA) {
		return nil, serrors.New("signing subject is different from CSR subject",
			"csr_isd_as", csrIA, "chain_isd_as", chainIA)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, serrors.WrapStr("invalid CSR signature", err)
	}
	return csr, nil
}
