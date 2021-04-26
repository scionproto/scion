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

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/file"
)

// NewKeyPrivateCmd returns a cobra command that generates new private keys.
func NewKeyPrivateCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		curve string
		force bool
	}
	var cmd = &cobra.Command{
		Use:   "private [flags] <private-key-file>",
		Short: "Generate private key at the specified location",
		Example: fmt.Sprintf(`  %[1]s private cp-as.key
  %[1]s private --curve P-384 cp-as.key`, pather.CommandPath()),
		Long: `'private' generates a PEM encoded private key at the specified location.

The contents are the private key in PKCS #8 ASN.1 DER format.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			filename := args[0]
			if err := file.CheckDirExists(filepath.Dir(filename)); err != nil {
				return serrors.WrapStr("checking that directory of private key exists", err)
			}
			key, err := GeneratePrivateKey(flags.curve)
			if err != nil {
				return serrors.WrapStr("generating private key", err)
			}
			raw, err := EncodePEMPrivateKey(key)
			if err != nil {
				return serrors.WrapStr("encoding private key", err)
			}
			if err := file.WriteFile(filename, raw, 0600, file.WithForce(flags.force)); err != nil {
				return serrors.WrapStr("writing private key", err)
			}
			fmt.Printf("Private key successfully written to %q\n", filename)
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.curve, "curve", "P-256",
		"The elliptic curve to use (P-256|P-384|P-521)",
	)
	cmd.Flags().BoolVar(&flags.force, "force", false,
		"Force overwritting existing private key",
	)
	return cmd
}

// GeneratePrivateKey generates a new private key.
func GeneratePrivateKey(curve string) (crypto.PrivateKey, error) {
	switch strings.ToLower(curve) {
	case "p-256", "p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p-384", "p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p-521", "p521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, serrors.New("unsupported curve", "curve", curve)
	}
}

// EncodePEMPrivateKey encodes the private key in PEM format.
func EncodePEMPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	p := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: raw,
	})
	if p == nil {
		panic("PEM encoding failed")
	}
	return p, nil
}
