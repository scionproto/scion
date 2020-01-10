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
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/keys"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

type signatureGen struct {
	Dirs    pkicmn.Dirs
	Version scrypto.Version
}

// trcParts maps file names to the partially signed TRC parts.
type trcParts map[string]trc.Signed

func (g signatureGen) Run(asMap pkicmn.ASMap) error {
	l := loader{Dirs: g.Dirs, Version: g.Version}
	cfgs, err := l.LoadConfigs(asMap.ISDs())
	if err != nil {
		return serrors.WrapStr("unable to load TRC configs", err)
	}
	protos, err := l.LoadProtos(cfgs)
	if err != nil {
		return serrors.WrapStr("unable to load prototype TRCs", err)
	}
	parts, err := g.Generate(asMap, cfgs, protos)
	if err != nil {
		return serrors.WrapStr("unable to sign prototype TRCs", err)
	}
	if err := g.write(parts); err != nil {
		return serrors.WrapStr("unable to write signed TRCs", err)
	}
	return nil
}

func (g signatureGen) Generate(asMap pkicmn.ASMap, cfgs map[addr.ISD]conf.TRC,
	protos map[addr.ISD]signedMeta) (map[addr.ISD]trcParts, error) {

	parts := make(map[addr.ISD]trcParts)
	for isd, ias := range asMap {
		t, err := protos[isd].Signed.EncodedTRC.Decode()
		if err != nil {
			return nil, serrors.WrapStr("unable to parse prototype TRC payload", err, "isd", isd)
		}
		parts[isd] = make(trcParts)
		for _, ia := range ias {
			if _, ok := cfgs[isd].PrimaryASes[ia.A]; !ok {
				continue
			}
			_, vote := t.Votes[ia.A]
			if !vote && !(len(t.ProofOfPossession[ia.A]) > 0) {
				pkicmn.QuietPrint("Skipping non-signing primary AS %s\n", ia)
				continue
			}
			signed, err := g.generate(ia, cfgs[isd], protos[ia.I].Signed, t)
			if err != nil {
				return nil, serrors.WrapStr("unable to generate signed TRC", err, "ia", ia)
			}
			file := PartsFile(g.Dirs.Out, ia, protos[ia.I].Version)
			parts[isd][file] = signed
		}
	}
	return parts, nil
}

func (g signatureGen) generate(ia addr.IA, cfg conf.TRC, signed trc.Signed,
	t *trc.TRC) (trc.Signed, error) {

	if err := g.sanityChecks(ia.I, cfg, t); err != nil {
		return trc.Signed{}, serrors.WrapStr("sanity checks failed", err)
	}
	signatures := make(map[trc.Protected]trc.Signature)
	if err := g.castVote(signatures, ia, cfg, signed, t); err != nil {
		return trc.Signed{}, serrors.WrapStr("unable to cast vote", err)
	}
	if err := g.showPOP(signatures, ia, cfg, signed, t); err != nil {
		return trc.Signed{}, serrors.WrapStr("unable to show proof of possession", err)
	}
	s := trc.Signed{
		EncodedTRC: signed.EncodedTRC,
		Signatures: sortSignatures(signatures),
	}
	return s, nil
}

// sanityChecks does some small sanity checks to ensure the right TRC is signed.
func (g signatureGen) sanityChecks(isd addr.ISD, cfg conf.TRC, t *trc.TRC) error {
	if isd != t.ISD {
		return serrors.New("ISD does not match", "proto", t.ISD, "cfg", isd)
	}
	if cfg.Version != t.Version {
		return serrors.New("version does not match", "proto", t.Version, "cfg", cfg.Version)
	}
	if cfg.BaseVersion != t.BaseVersion {
		return serrors.New("base_version does not match", "proto", t.BaseVersion,
			"cfg", cfg.BaseVersion)
	}
	return nil
}

func (g signatureGen) castVote(signatures map[trc.Protected]trc.Signature, ia addr.IA,
	cfg conf.TRC, signed trc.Signed, t *trc.TRC) error {

	keyType, ok := t.Votes[ia.A]
	if !ok {
		return nil
	}
	prev, _, err := loadTRC(SignedFile(g.Dirs.Out, t.ISD, t.Version-1))
	if err != nil {
		return err
	}
	id := keyconf.ID{
		IA:      ia,
		Version: prev.PrimaryASes[ia.A].Keys[keyType].KeyVersion,
	}
	id.Usage, err = keys.UsageFromTRCKeyType(keyType)
	if err != nil {
		return err
	}
	priv, err := g.loadKey(id)
	if err != nil {
		return err
	}
	protected := trc.Protected{
		AS:         ia.A,
		Algorithm:  priv.Algorithm,
		KeyType:    keyType,
		KeyVersion: priv.Version,
		Type:       trc.VoteSignature,
	}
	signature, err := g.sign(protected, signed, priv)
	if err != nil {
		return err
	}
	signatures[protected] = signature
	pkicmn.QuietPrint("Primary %s casts vote using %s key\n", ia, keyType)
	return nil
}

func (g signatureGen) showPOP(signatures map[trc.Protected]trc.Signature, ia addr.IA,
	cfg conf.TRC, signed trc.Signed, t *trc.TRC) error {

	for _, keyType := range t.ProofOfPossession[ia.A] {
		id := keyconf.ID{
			IA:      ia,
			Version: t.PrimaryASes[ia.A].Keys[keyType].KeyVersion,
		}
		var err error
		id.Usage, err = keys.UsageFromTRCKeyType(keyType)
		if err != nil {
			return err
		}
		priv, err := g.loadKey(id)
		if err != nil {
			return err
		}
		protected := trc.Protected{
			AS:         ia.A,
			Algorithm:  priv.Algorithm,
			KeyType:    keyType,
			KeyVersion: priv.Version,
			Type:       trc.POPSignature,
		}
		signature, err := g.sign(protected, signed, priv)
		if err != nil {
			return err
		}
		signatures[protected] = signature
		pkicmn.QuietPrint("Primary %s shows POP for %s key\n", ia, keyType)
	}
	return nil
}

func (g signatureGen) loadKey(id keyconf.ID) (keyconf.Key, error) {
	file := keys.PrivateFile(g.Dirs.Out, id)
	priv, err := keyconf.LoadKeyFromFile(file, keyconf.PrivateKey, id)
	if err != nil {
		return keyconf.Key{}, serrors.WrapStr("unable to load private key", err, "file", file)
	}
	return priv, nil
}

func (g signatureGen) sign(protected trc.Protected, signed trc.Signed,
	priv keyconf.Key) (trc.Signature, error) {

	encProtected, err := trc.EncodeProtected(protected)
	if err != nil {
		return trc.Signature{}, serrors.WrapStr("unable to encode protected", err)
	}
	sig, err := scrypto.Sign(trc.SigInput(encProtected, signed.EncodedTRC),
		priv.Bytes, priv.Algorithm)
	if err != nil {
		return trc.Signature{}, serrors.WrapStr("unable to sign", err)
	}
	signature := trc.Signature{
		EncodedProtected: encProtected,
		Signature:        sig,
	}
	return signature, nil
}

func (g signatureGen) write(signatures map[addr.ISD]trcParts) error {
	for _, files := range signatures {
		for file, signed := range files {
			raw, err := trc.EncodeSigned(signed)
			if err != nil {
				return serrors.WrapStr("unable to encode signed TRC", err, "file", file)
			}
			pkicmn.WriteToFile(raw, file, 0644)
		}
	}
	return nil
}
