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

package trcs

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

type validator struct {
	Dirs pkicmn.Dirs
}

// Validate checks that all TRCs in the map are valid and verifiable. For base
// TRCs, the TRC invariants are validated and all proof of possessions are
// verified. TRC updates are validated and verified based on the previous TRC.
func (v validator) Validate(combined map[addr.ISD]signedMeta) error {
	for isd, meta := range combined {
		if err := v.validate(isd, meta); err != nil {
			return serrors.WrapStr("TRC cannot be validated/verified", err, "isd", isd)
		}
	}
	return nil
}

func (v validator) validate(isd addr.ISD, meta signedMeta) error {
	t, err := meta.Signed.EncodedTRC.Decode()
	if err != nil {
		return serrors.WrapStr("invalid TRC payload", err)
	}
	if err := t.ValidateInvariant(); err != nil {
		return serrors.WrapStr("violated TRC invariant", err)
	}
	pop := trc.POPVerifier{
		TRC:        t,
		Encoded:    meta.Signed.EncodedTRC,
		Signatures: meta.Signed.Signatures,
	}
	if err := pop.Verify(); err != nil {
		return serrors.WrapStr("proof of possesions fail to verify", err)
	}
	if t.Base() {
		return nil
	}
	prev, _, err := loadTRC(SignedFile(v.Dirs.Out, isd, meta.Version-1))
	if err != nil {
		return serrors.WrapStr("unable to load previous TRC", err, "version", meta.Version-1)
	}
	val := trc.UpdateValidator{
		Next: t,
		Prev: prev,
	}
	if _, err := val.Validate(); err != nil {
		return serrors.WrapStr("unable to validate TRC update", err)
	}
	ver := trc.UpdateVerifier{
		Next:        t,
		NextEncoded: meta.Signed.EncodedTRC,
		Signatures:  meta.Signed.Signatures,
		Prev:        prev,
	}
	if err := ver.Verify(); err != nil {
		return serrors.WrapStr("unable to verify TRC update", err)
	}
	return nil
}
