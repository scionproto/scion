// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package cert_mgmt

import (
	"crypto/x509"
	"fmt"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*ChainRenewalRequest)(nil)

// ChainRenewalRequest is a request for chain renewal.
type ChainRenewalRequest struct {
	// RawCSR contains the certificate request encoded in the ASN.1 DER format.
	RawCSR    []byte       `capnp:"csr"`
	Signature *proto.SignS `capnp:"sign"`
}

func (c *ChainRenewalRequest) ProtoId() proto.ProtoIdType {
	return proto.CertChainRenewalRequest_TypeID
}

// CertificateRequest parses the raw certificate request.
func (c *ChainRenewalRequest) CertificateRequest() (*x509.CertificateRequest, error) {
	return x509.ParseCertificateRequest(c.RawCSR)
}

func (c *ChainRenewalRequest) String() string {
	csr, err := c.CertificateRequest()
	if err != nil {
		return fmt.Sprintf("Invalid renewal req: %v", err)
	}
	ia, err := cppki.ExtractIA(csr.Subject)
	if err != nil || ia == nil {
		return fmt.Sprintf("CSR with missing IA, subject: %s, err: %v", csr.Subject, err)
	}
	return fmt.Sprintf("CSR: IA: %s", *ia)
}
