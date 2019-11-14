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

// Run checks that all TRCs provided in the file list are valid and verifiable.
func (v validator) Run(files []string) error {
	var errs serrors.List
	trcs := make(map[addr.ISD]signedMeta)
	for _, file := range files {
		dec, err := loadTRC(file)
		if err != nil {
			errs = append(errs, serrors.WrapStr("unable to load TRC", err, "file", file))
			continue
		}
		trcs[dec.TRC.ISD] = signedMeta{Signed: dec.Signed, Version: dec.TRC.Version}
	}
	if err := v.Validate(trcs); err != nil {
		errs = append(errs, err)
	}
	return errs.ToError()
}

// Validate checks that all TRCs in the map are valid and verifiable. For base
// TRCs, the TRC invariants are validated and all proof of possessions are
// verified. TRC updates are validated and verified based on the previous TRC.
func (v validator) Validate(combined map[addr.ISD]signedMeta) error {
	var errs serrors.List
	for isd, meta := range combined {
		if err := v.validate(isd, meta); err != nil {
			errs = append(errs, serrors.WrapStr("TRC cannot be validated/verified", err,
				"isd", isd, "version", meta.Version))
		}
	}
	return errs.ToError()
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
	dec, err := loadTRC(SignedFile(v.Dirs.Out, isd, meta.Version-1))
	if err != nil {
		return serrors.WrapStr("unable to load previous TRC", err, "version", meta.Version-1)
	}
	val := trc.UpdateValidator{
		Next: t,
		Prev: dec.TRC,
	}
	if _, err := val.Validate(); err != nil {
		return serrors.WrapStr("unable to validate TRC update", err)
	}
	ver := trc.UpdateVerifier{
		Next:        t,
		NextEncoded: meta.Signed.EncodedTRC,
		Signatures:  meta.Signed.Signatures,
		Prev:        dec.TRC,
	}
	if err := ver.Verify(); err != nil {
		return serrors.WrapStr("unable to verify TRC update", err)
	}
	return nil
}
