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

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust"
)

// NewChainRenewalRequest builds a ChainRenewalRequest given a serialized CSR
// and a signer.
func NewChainRenewalRequest(ctx context.Context, csr []byte,
	signer trust.Signer) (*cert_mgmt.ChainRenewalRequest, error) {
	meta, err := signer.Sign(ctx, csr)
	if err != nil {
		return nil, err
	}
	return &cert_mgmt.ChainRenewalRequest{
		RawCSR:    csr,
		Signature: meta,
	}, nil
}

// VerifyChainRenewalRequest verifies the renewal request. It checks that the
// contained CSR is valid and correctly self-signed, and that the signature is
// valid and can be verified by a chain in the given chains.
func VerifyChainRenewalRequest(target *cert_mgmt.ChainRenewalRequest,
	chains [][]*x509.Certificate) (*x509.CertificateRequest, error) {

	if target == nil || target.RawCSR == nil || target.Signature == nil {
		return nil, serrors.New("incomplete ChainRenewalRequest,")
	}
	csr, err := target.CertificateRequest()
	if err != nil {
		return nil, serrors.WrapStr("could not parse CSR in request", err)
	}
	csrIA, err := cppki.ExtractIA(csr.Subject)
	if err != nil {
		return nil, serrors.WrapStr("could not extract IA from CSR.Subject", err)
	}
	if csrIA == nil {
		return nil, serrors.New("empty IA in CSR.Subject")
	}
	src, err := ctrl.NewX509SignSrc(target.Signature.Src)
	if err != nil {
		return nil, serrors.WrapStr("invalid sign src", err)
	}
	if !csrIA.Equal(src.IA) {
		return nil, serrors.New("signature doesn't identify CSR",
			"csr.IA", csrIA, "sign.IA", src.IA)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, serrors.WrapStr("invalid CSR signature", err)
	}
	input := target.Signature.SigInput(target.RawCSR, false)
	for _, chain := range chains {
		asCrt := chain[0]
		err := asCrt.CheckSignature(asCrt.SignatureAlgorithm, input, target.Signature.Signature)
		if err == nil {
			return csr, nil
		}
	}
	return nil, serrors.New("no provided chain can verify the signature")
}
