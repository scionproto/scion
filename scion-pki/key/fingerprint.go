// Copyright 2022 Anapaya Systems
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

package key

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/encoding"
)

// NewFingerprintCmd returns a cobra command that returns the subject key ID of a
// public key. If a private key is given, the subject key ID is computed for the
// corresponding public key. For certificated or certificates chains, the subject
// key ID is computed with respect to the public key of the first certificate in the file.
func NewFingerprintCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		fullKey bool
		format  string
	}
	var cmd = &cobra.Command{
		Use:   "fingerprint [flags] <key-file>",
		Short: "Computes the fingerprint of the provided key",
		Example: fmt.Sprintf(`  %[1]s fingerprint cp-as.key --format base64
  %[1]s fingerprint ISD1-ASff00_-_110.pem --full-key-digest`, pather.CommandPath()),
		Long: `'fingerprint' computes the fingerprint of the provided key.

The fingerprint of a private key will be based on the public part of the key. For certificates or
certificate chains the fingerprint is computed on the public key of the first certificate
in the file.

By default the fingerprint calculated is SHA-1 hash of the marshaled public key as defined in
https://tools.ietf.org/html/rfc5280#section-4.2.1.2 (1). With the '--full-key-digest' flag, 
the computed fingerprint is the SHA-1 hash with ASN.1 DER-encoded subjectPublicKey.

The subject key ID is written to standard out.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := encoding.CheckEncodings(flags.format)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true

			filename := args[0]
			pub, err := loadPublicKey(filename)
			if err != nil {
				return err
			}
			var skid []byte
			if flags.fullKey {
				marshaledKey, err := x509.MarshalPKIXPublicKey(pub)
				if err != nil {
					return serrors.WrapStr("full-key-digest", err)
				}
				cks := sha1.Sum(marshaledKey)
				skid = cks[:]
			} else {
				skid, err = cppki.SubjectKeyID(pub)
				if err != nil {
					return serrors.WrapStr("computing subject key ID", err)
				}
			}
			output, err := encoding.EncodeBytes(skid, flags.format)
			if err != nil {
				return serrors.WrapStr("encoding subject key ID", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), output)
			return nil
		},
	}
	cmd.Flags().BoolVar(&flags.fullKey, "full-key-digest", false,
		"Calculate the SHA1 sum of the marshaled public key",
	)
	cmd.Flags().StringVar(&flags.format, "format", "emoji",
		`The format of the fingerprint (hex|base64|base64-url|base64-raw|base64-url-raw|emoji).`,
	)
	return cmd
}

// loadPublicKey loads the public key from file and distinguishes what type of key it is.
func loadPublicKey(filename string) (crypto.PublicKey, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, serrors.WrapStr("reading input file", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, serrors.New("parsing input failed")
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, serrors.WrapStr("parsing private key", err)
		}

		pub, ok := key.(crypto.Signer)
		if !ok {
			return nil, serrors.New("unsupported private key type",
				"type", fmt.Sprintf("%T", key),
			)
		}
		return pub.Public(), nil
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, serrors.WrapStr("parsing public key", err)
		}
		return pub, nil
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, serrors.WrapStr("parsing certificate", err)
		}
		return cert.PublicKey, nil
	default:
		return nil, serrors.New("unsupported PEM block", "type", block.Type)
	}

}
