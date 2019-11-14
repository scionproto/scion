// Copyright 2019 Anapaya Systems
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

package certs

import (
	"io/ioutil"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/trcs"
)

type verifier struct {
	Dirs pkicmn.Dirs
}

// VerifyIssuer validates and verifies a raw signed issuer certificate. For
// verification, the issuing TRC is loaded from the file system.
func (v verifier) VerifyIssuer(raw []byte) error {
	signed, err := cert.ParseSignedIssuer(raw)
	if err != nil {
		return serrors.WrapStr("unable to parse signed issuer certificate", err)
	}
	c, err := signed.Encoded.Decode()
	if err != nil {
		return serrors.WrapStr("unable to parse issuer certificate payload", err)
	}
	if err := c.Validate(); err != nil {
		return serrors.WrapStr("unable to validate issuer certificate", err)
	}
	t, err := v.loadTRC(c.Subject.I, c.Issuer.TRCVersion)
	if err != nil {
		return err
	}
	issVer := cert.IssuerVerifier{
		Issuer:       c,
		SignedIssuer: &signed,
		TRC:          t,
	}
	if err := issVer.Verify(); err != nil {
		return serrors.WrapStr("unable to verify issuer certificate", err)
	}
	return nil
}

func (v verifier) loadTRC(isd addr.ISD, version scrypto.Version) (*trc.TRC, error) {
	raw, err := ioutil.ReadFile(trcs.SignedFile(v.Dirs.Out, isd, version))
	if err != nil {
		return nil, serrors.WrapStr("unable to read issuing TRC", err)
	}
	signed, err := trc.ParseSigned(raw)
	if err != nil {
		return nil, serrors.WrapStr("unable to parse issuing TRC", err)
	}
	t, err := signed.EncodedTRC.Decode()
	if err != nil {
		return nil, serrors.WrapStr("unable to decode issuing TRC payload", err)
	}
	return t, nil
}
