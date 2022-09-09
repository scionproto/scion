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
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/file"
)

// NewFingerprintCmd returns a cobra command that returns the subject key id of a
// public key. If a private key is given, the subject key id is computed for the
// corresponding public key. For certificated or certificates chains, the subject
// key id is computed with respect to the public key of the first certificate in the file.
func NewFingerprintCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		out     string
		fullKey bool
		force   bool
	}
	var cmd = &cobra.Command{
		Use:   "fingerprint [flags] <key-file>",
		Short: "Computes the subject key id fingerprint of the provided key",
		Example: fmt.Sprintf(`  %[1]s fingerprint cp-as.key
  %[1]s fingerprint --full-key-digest ISD1-ASff00_-_110.pem`, pather.CommandPath()),
		Long: `'fingerprint' computes the subject key id fingerprint of a public key.

If the private key is given, compute on the corresponding public key. For certificates or certificate chains 
the fingerprint is computed on the public key of the first certificate in the file.

By default, the subject key id is written to standard out.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			filename := args[0]
			pub, err := LoadPublicKey(filename)
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
			if flags.out == "" {
				fmt.Printf("%c\n", skid)
				return nil
			}
			fmt.Printf("testing: %c\n", skid)
			fmt.Println(skid)
			// Write subject key id to file system instead of stdout.
			if err := file.CheckDirExists(filepath.Dir(flags.out)); err != nil {
				return serrors.WrapStr("checking that directory of public key exists", err)
			}
			if err = file.WriteFile(flags.out, skid, 0600, file.WithForce(flags.force)); err != nil {
				return serrors.WrapStr("writing subject key id", err)
			}
			fmt.Printf("Public key successfully written to %q\n", flags.out)
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.out, "out", "",
		"Path to write subject key id",
	)
	cmd.Flags().BoolVar(&flags.fullKey, "full-key-digest", false,
		"Calculate the SHA1 sum of the marshaled public key",
	)
	cmd.Flags().BoolVar(&flags.force, "force", false,
		"Force overwritting existing output file",
	)
	return cmd
}

// LoadPublicKey loads the public key from file and distinguishes what type of key it is.
func LoadPublicKey(filename string) (crypto.PublicKey, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, serrors.WrapStr("reading private key", err)
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
			return nil, serrors.New("cannot get public key from private key",
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
			return nil, serrors.WrapStr("error parsing certificate", err)
		}
		return cert.PublicKey, nil
	default:
		return nil, serrors.New("file is not a valid PEM encoding of a private/public key or certificate", "type", block.Type)
	}

}
