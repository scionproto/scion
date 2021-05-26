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
	"io/ioutil"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/key"
)

func newSign(pather command.Pather) *cobra.Command {
	var flags struct {
		out    string
		outDir string
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
`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return RunSign(args[0], args[1], args[2], flags.out, flags.outDir)
		},
	}

	cmd.Flags().StringVarP(&flags.out, "out", "o", "", "Output file path. If --out is set, "+
		"--out-dir is ignored. If not set, the output is written to "+
		"ISD<isd>-B<base_version>-S<serial_number>.<signing-ia>-<signature-type>.trc")
	cmd.Flags().StringVar(&flags.outDir, "out-dir", ".", "Output directory. If --out is set, "+
		"--out-dir is ignored.")

	return cmd
}

func RunSign(pld, certfile, keyfile, out, outDir string) error {
	// Read TRC payload
	rawPld, err := ioutil.ReadFile(pld)
	if err != nil {
		return serrors.WrapStr("error loading payload", err)
	}
	pldBlock, _ := pem.Decode(rawPld)
	if pldBlock != nil && pldBlock.Type == "TRC PAYLOAD" {
		rawPld = pldBlock.Bytes
	}
	// Load signing key
	priv, err := key.LoadPrivateKey(keyfile)
	if err != nil {
		return err
	}
	// Load signing cert
	rawCert, err := ioutil.ReadFile(certfile)
	if err != nil {
		return serrors.WrapStr("error loading signer", err)
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
		return serrors.WrapStr("error parsing signer", err)
	}
	signed, err := sign(rawPld, priv, cert)
	if err != nil {
		return serrors.WrapStr("error signing TRC payload", err)
	}
	// Verify the signed TRC payload as a sanity check
	signedTRC, err := cppki.DecodeSignedTRC(signed)
	if err != nil {
		return serrors.WrapStr("error decoding signed TRC payload", err)
	}
	if err := verifyBundle(signedTRC, []*x509.Certificate{cert}); err != nil {
		return serrors.WrapStr("error verifying singed TRC payload", err)
	}
	signed = pem.EncodeToMemory(&pem.Block{
		Type:  "TRC",
		Bytes: signed,
	})
	fname, err := outPath(out, outDir, &signedTRC.TRC, cert)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(fname, signed, 0644); err != nil {
		return serrors.WrapStr("error writing signed TRC paylod", err)
	}
	fmt.Printf("Successfully signed TRC payload at %s\n", out)
	return nil
}

func sign(pld []byte, signer crypto.Signer, cert *x509.Certificate) ([]byte, error) {
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
		return "", serrors.WrapStr("extracting ISD-AS from signing certificate", err)
	}
	signType, err := signatureType(trc, cert)
	if err != nil {
		return "", serrors.WrapStr("determining cert type", err)
	}
	fname := fmt.Sprintf("ISD%d-B%d-S%d.%s-%s.trc", trc.ID.ISD, trc.ID.Base, trc.ID.Serial,
		ia.FileFmt(false), signType)
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
