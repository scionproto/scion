// Copyright 2021 Anapaya Systems
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
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	scionpki "github.com/scionproto/scion/scion-pki"
	"github.com/scionproto/scion/scion-pki/key"
)

func newSign(pather command.Pather) *cobra.Command {
	var flags struct {
		out    string
		outDir string
		kms    string
	}

	cmd := &cobra.Command{
		Use:   "sign <payload_file> <crt_file> <key_file> [flags]",
		Short: "Sign a TRC",
		Example: fmt.Sprintf(
			`  %[1]s sign ISD1-B1-S1.pld.der sensitive-voting.crt sensitive-voting.key
  %[1]s sign ISD1-B1-S1.pld.der regular-voting.crt regular-voting.key --out ISD1-B1-S1.regular.trc`,
			pather.CommandPath()),
		Long: `'sign' signs a TRC payload with the signing key and signing certificate.

Voting, proof-of-possession, and root acknowledgement signatures can be added by using the
corresponding signing keys and certificates.

By default, the resulting signed object is written to a file with the following
naming pattern::

	ISD<isd>-B<base_version>-S<serial_number>.<signing-isd_as>-<signature-type>.trc

An alternative name can be specified with the \--out flag.

If 'dummy' is provided as the payload file, a dummy TRC payload is signed. This is useful for
testing access to the necessary cryptographic material, especially in preparation for
a TRC signing ceremony.
`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return RunSign(args[0], args[1], args[2], flags.kms, flags.out, flags.outDir)
		},
	}

	cmd.Flags().StringVarP(&flags.out, "out", "o", "", "Output file path. "+
		"If --out is set, --out-dir is ignored.",
	)
	cmd.Flags().StringVar(&flags.outDir, "out-dir", ".", "Output directory. "+
		"If --out is set, --out-dir is ignored.")
	scionpki.BindFlagKms(cmd.Flags(), &flags.kms)
	return cmd
}

func RunSign(pld, certfile, keyName, kms, out, outDir string) error {
	dummy := pld == "dummy"

	// Read TRC payload
	rawPld, err := func() ([]byte, error) {
		if !dummy {
			return os.ReadFile(pld)
		}
		return dummyPayload, nil
	}()
	if err != nil {
		return serrors.Wrap("error loading payload", err)
	}
	pldBlock, _ := pem.Decode(rawPld)
	if pldBlock != nil && pldBlock.Type == "TRC PAYLOAD" {
		rawPld = pldBlock.Bytes
	}
	// Load signing key
	priv, err := key.LoadPrivateKey(kms, keyName)
	if err != nil {
		return err
	}
	// Load signing cert
	rawCert, err := os.ReadFile(certfile)
	if err != nil {
		return serrors.Wrap("error loading signer", err)
	}
	certBlock, rest := pem.Decode(rawCert)
	if certBlock != nil {
		if certBlock.Type != "CERTIFICATE" {
			return serrors.New("signer is not a certificate")
		}
		if len(rest) > 0 {
			return serrors.New("signer contains more than one certificate")
		}
		rawCert = certBlock.Bytes
	}
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return serrors.Wrap("error parsing signer", err)
	}
	signed, err := SignPayload(rawPld, priv, cert)
	if err != nil {
		return serrors.Wrap("error signing TRC payload", err)
	}
	// Verify the signed TRC payload as a sanity check
	signedTRC, err := cppki.DecodeSignedTRC(signed)
	if err != nil {
		return serrors.Wrap("error decoding signed TRC payload", err)
	}
	if err := verifyBundle(signedTRC, []*x509.Certificate{cert}); err != nil {
		return serrors.Wrap("error verifying singed TRC payload", err)
	}
	signed = pem.EncodeToMemory(&pem.Block{
		Type:  "TRC",
		Bytes: signed,
	})
	fname, err := outPath(out, outDir, &signedTRC.TRC, cert)
	if err != nil {
		return err
	}
	if err := os.WriteFile(fname, signed, 0644); err != nil {
		return serrors.Wrap("error writing signed TRC paylod", err)
	}

	if !dummy {
		fmt.Printf("Successfully signed TRC payload at %s\n", out)
	} else {
		fmt.Println("Successfully signed dummy TRC payload")
	}
	return nil
}

func SignPayload(pld []byte, signer crypto.Signer, cert *x509.Certificate) ([]byte, error) {
	eci, err := protocol.NewDataEncapsulatedContentInfo(pld)
	if err != nil {
		return nil, err
	}
	sd, err := protocol.NewSignedData(eci)
	if err != nil {
		return nil, err
	}
	if err := sd.AddSignerInfo([]*x509.Certificate{cert}, signer); err != nil {
		return nil, err
	}
	// AddSignerInfo also adds the signing certificate to the CMS envelop, however, as it's already
	// included in the TRC payload or in the previous TRC in case of a vote, we remove it again.
	sd.Certificates = []asn1.RawValue{}

	return sd.ContentInfoDER()
}

func outPath(out, outDir string, trc *cppki.TRC, cert *x509.Certificate) (string, error) {
	if out != "" {
		return out, nil
	}
	ia, err := cppki.ExtractIA(cert.Subject)
	if err != nil {
		return "", serrors.Wrap("extracting ISD-AS from signing certificate", err)
	}
	signType, err := signatureType(trc, cert)
	if err != nil {
		return "", serrors.Wrap("determining cert type", err)
	}
	fname := fmt.Sprintf("ISD%d-B%d-S%d.%s-%s.trc", trc.ID.ISD, trc.ID.Base, trc.ID.Serial,
		addr.FormatIA(ia, addr.WithFileSeparator()), signType)
	return filepath.Join(outDir, fname), nil
}

func signatureType(trc *cppki.TRC, cert *x509.Certificate) (string, error) {
	certType, err := cppki.ValidateCert(cert)
	if err != nil {
		return "", err
	}
	inTRC := find(cert, trc.Certificates)
	switch certType {
	case cppki.Sensitive:
		if inTRC {
			return "sensitive", nil
		}
		return "sensitive-vote", nil
	case cppki.Regular:
		if inTRC {
			return "regular", nil
		}
		return "regular-vote", nil
	case cppki.Root:
		return "root-ack", nil
	}
	return "", serrors.New("invalid signing cert type")
}

func find(cert *x509.Certificate, certs []*x509.Certificate) bool {
	for _, c := range certs {
		if bytes.Equal(c.Raw, cert.Raw) {
			return true
		}
	}
	return false
}
