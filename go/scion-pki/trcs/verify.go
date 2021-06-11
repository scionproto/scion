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

package trcs

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cms/oid"
	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
)

func newVerify(pather command.Pather) *cobra.Command {
	var flags struct {
		anchor string
	}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a TRC chain",
		Example: fmt.Sprintf(`  %[1]s verify --anchor bundle.pem ISD1-B1-S1.trc
  %[1]s verify --anchor ISD1-B1-S1.trc ISD1-B1-S2.trc ISD1-B1-S3.trc`, pather.CommandPath()),
		Long: `'verify' verifies a TRC chain based on a trusted anchor point.

The anchor can either be a collection of trusted certificates bundled in a PEM
file, or a trusted TRC. TRC update chains that start with a base TRC can be
verified with either type of anchor. TRC update chains that start with a
non-base TRC must have a TRC as anchor.
`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return RunVerify(args, flags.anchor)
		},
	}

	cmd.Flags().StringVarP(&flags.anchor, "anchor", "a", "", "trust anchor (required)")
	cmd.MarkFlagRequired("anchor")
	return cmd
}

// RunVerify runs verification of the TRC files from the given anchor.
func RunVerify(files []string, anchor string) error {
	var trcs []cppki.SignedTRC
	for _, name := range files {
		dec, err := DecodeFromFile(name)
		if err != nil {
			return serrors.WrapStr("error decoding TRC", err, "file", name)
		}
		trcs = append(trcs, dec)
	}
	isd, base := trcs[0].TRC.ID.ISD, trcs[0].TRC.ID.Base
	for _, dec := range trcs {
		if isd != dec.TRC.ID.ISD {
			return serrors.New("multiple ISDs", "isds", []addr.ISD{isd, dec.TRC.ID.ISD})
		}
		if base != dec.TRC.ID.Base {
			return serrors.New("multiple base versions", "bases", []scrypto.Version{
				base, dec.TRC.ID.Base})
		}
	}
	sort.Slice(trcs, func(i, j int) bool {
		return trcs[i].TRC.ID.Serial < trcs[j].TRC.ID.Serial
	})
	serials := []scrypto.Version{trcs[0].TRC.ID.Serial}
	for i := 1; i < len(trcs); i++ {
		serials = append(serials, trcs[i].TRC.ID.Serial)
		if serials[i] != serials[i-1]+1 {
			return serrors.New("gap in TRC update chain", "serial numbers", serials)
		}
	}
	if err := verifyInitial(trcs[0], anchor); err != nil {
		return serrors.WrapStr("verifying first TRC in update chain", err, "id", trcs[0].TRC.ID)
	}
	fmt.Println("Verified TRC successfully:", trcs[0].TRC.ID)
	for i := 1; i < len(trcs); i++ {
		if err := trcs[i].Verify(&trcs[i-1].TRC); err != nil {
			return serrors.WrapStr("verifying TRC update", err, "id", trcs[i].TRC.ID)
		}
		fmt.Println("Verified TRC successfully:", trcs[i].TRC.ID)
	}
	return nil
}

func verifyInitial(trc cppki.SignedTRC, anchor string) error {
	if !trc.TRC.ID.IsBase() {
		a, err := DecodeFromFile(anchor)
		if err != nil {
			return serrors.WrapStr("loading TRC anchor", err, "anchor", anchor)
		}
		return trc.Verify(&a.TRC)
	}

	if err := trc.Verify(nil); err != nil {
		return serrors.WrapStr("verifying proof of possession", err)
	}
	certs, err := loadAnchorCerts(anchor)
	if err != nil {
		return serrors.WithCtx(err, "anchor", anchor)
	}
	if err := verifyBundle(trc, certs); err != nil {
		return serrors.WrapStr("checking verifiable with bundled certificates", err)
	}
	return nil
}

func loadAnchorCerts(file string) ([]*x509.Certificate, error) {
	if info, err := os.Stat(file); err != nil {
		return nil, err
	} else if info.IsDir() {
		return nil, serrors.New("anchor is a directory")
	}
	dec, trcErr := DecodeFromFile(file)
	if trcErr == nil {
		return dec.TRC.Certificates, nil
	}
	certs, certErr := cppki.ReadPEMCerts(file)
	if certErr == nil {
		return certs, nil
	}
	errs := serrors.List{trcErr, certErr}
	return nil, serrors.WrapStr("anchor contents not supported", errs.ToError())
}

func verifyBundle(signed cppki.SignedTRC, certs []*x509.Certificate) error {
	if len(signed.SignerInfos) == 0 {
		return serrors.New("no signatures found")
	}
	for i, si := range signed.SignerInfos {
		if err := verifySignerInfo(si, signed.TRC.Raw, certs); err != nil {
			return serrors.WithCtx(err, "index", i)
		}
	}
	return nil
}

func verifySignerInfo(si protocol.SignerInfo, pld []byte, certs []*x509.Certificate) error {
	if si.SignedAttrs == nil {
		return serrors.New("SignerInfo without signed attributes")
	}
	siContentType, err := si.GetContentTypeAttribute()
	if err != nil {
		return serrors.WrapStr("error getting ContentType", err)
	}
	if !siContentType.Equal(oid.ContentTypeData) {
		return serrors.New("SignerInfo with invalid ContentType", "type", siContentType)
	}
	hash, err := si.Hash()
	if err != nil {
		return err
	}
	attrDigest, err := si.GetMessageDigestAttribute()
	if err != nil {
		return serrors.WrapStr("SignerInfo with invalid message digest", err)
	}
	actualDigest := hash.New()
	actualDigest.Write(pld)
	if !bytes.Equal(attrDigest, actualDigest.Sum(nil)) {
		return serrors.New("invalid SignerInfo message digest")
	}
	input, err := si.SignedAttrs.MarshaledForVerifying()
	if err != nil {
		return serrors.WrapStr("error marshalling signature input", err)
	}
	// FIXME(roosd): this also finds certificates based on subject key id.
	cert, err := si.FindCertificate(certs)
	if err != nil {
		return err
	}
	if err := cert.CheckSignature(si.X509SignatureAlgorithm(), input, si.Signature); err != nil {
		return err
	}
	// FIXME(roosd): Check timestamps
	return nil
}
