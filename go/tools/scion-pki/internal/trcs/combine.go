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
	"os"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

type combiner struct {
	Dirs    pkicmn.Dirs
	Version scrypto.Version
}

func (c combiner) Run(asMap pkicmn.ASMap) error {
	l := loader{Dirs: c.Dirs, Version: c.Version}
	cfgs, err := l.LoadConfigs(asMap.ISDs())
	if err != nil {
		return serrors.WrapStr("unable to load TRC configs", err)
	}
	protos, err := l.LoadProtos(cfgs)
	if err != nil {
		return serrors.WrapStr("unable to load prototype TRCs", err)
	}
	parts, err := l.LoadParts(protos)
	if err != nil {
		return serrors.WrapStr("unable to load parts", err)
	}
	combined, err := c.Combine(protos, parts)
	if err != nil {
		return serrors.WrapStr("unable to combine parts and prototype TRC", err)
	}
	if err := (validator{Dirs: c.Dirs}).Validate(combined); err != nil {
		return serrors.WrapStr("invalid combined TRCs generated", err)
	}
	if err := c.Write(combined); err != nil {
		return serrors.WrapStr("unable to write combined TRCs", err)
	}
	return nil
}

func (c combiner) Combine(protos map[addr.ISD]signedMeta,
	parts map[addr.ISD]trcParts) (map[addr.ISD]signedMeta, error) {

	combined := make(map[addr.ISD]signedMeta)
	for isd, proto := range protos {
		signatures := make(map[trc.Protected]trc.Signature)
		for fname, part := range parts[isd] {
			if proto.Signed.EncodedTRC != part.EncodedTRC {
				pkicmn.QuietPrint("Ignoring signed in %s. Payload is different\n", fname)
				continue
			}
			for _, sign := range part.Signatures {
				protected, err := sign.EncodedProtected.Decode()
				if err != nil {
					return nil, serrors.WrapStr("unable to parse protected", err, "file", fname)
				}
				if _, ok := signatures[protected]; ok {
					ia := addr.IA{I: isd, A: protected.AS}
					return nil, serrors.New("duplicate signature", "ia", ia,
						"key_type", protected.KeyType, "signature_type", protected.Type)
				}
				signatures[protected] = sign
			}
		}
		combined[isd] = signedMeta{
			Signed: trc.Signed{
				EncodedTRC: proto.Signed.EncodedTRC,
				Signatures: sortSignatures(signatures),
			},
			Version: proto.Version,
		}
	}
	return combined, nil
}

func (c combiner) Write(combined map[addr.ISD]signedMeta) error {
	for isd, meta := range combined {
		raw, err := trc.EncodeSigned(meta.Signed)
		if err != nil {
			return serrors.WrapStr("unable to encode signed TRC", err,
				"isd", isd, "version", meta.Version)
		}
		file := SignedFile(c.Dirs.Out, isd, meta.Version)
		dir := filepath.Dir(file)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return serrors.WrapStr("unable to make TRC directory", err, "isd", isd, "dir", dir)
		}
		if err := pkicmn.WriteToFile(raw, file, 0644); err != nil {
			return serrors.WrapStr("unable to write signed TRC", err,
				"isd", isd, "version", meta.Version)
		}
	}
	return nil
}
