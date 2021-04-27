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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/file"
)

// NewPublicCmd returns a cobra command that returns the public key for a
// given private key.
func NewPublicCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		out   string
		force bool
	}
	var cmd = &cobra.Command{
		Use:   "public [flags] <private-key-file>",
		Short: "Generate public key for the provided private key",
		Example: fmt.Sprintf(`  %[1]s public cp-as.key
  %[1]s public cp-as.key --out cp-as.pub`, pather.CommandPath()),
		Long: `'public' generates a PEM encoded public key.

By default, the public key is written to standard out.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			filename := args[0]
			priv, err := LoadPrivateKey(filename)
			if err != nil {
				return err
			}

			out, err := x509.MarshalPKIXPublicKey(priv.Public())
			if err != nil {
				return serrors.WrapStr("encoding public key", err)
			}
			encoded := pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: out,
			})
			if encoded == nil {
				panic("PEM encoding failed")
			}
			if flags.out == "" {
				fmt.Print(string(encoded))
				return nil
			}

			// Write public key to file system instead of stdout.
			if err := file.CheckDirExists(filepath.Dir(flags.out)); err != nil {
				return serrors.WrapStr("checking that directory of public key exists", err)
			}
			err = file.WriteFile(flags.out, encoded, 0644, file.WithForce(flags.force))
			if err != nil {
				return serrors.WrapStr("writing public key", err)
			}
			fmt.Printf("Public key successfully written to %q\n", flags.out)
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.out, "out", "",
		"Path to write public key",
	)
	cmd.Flags().BoolVar(&flags.force, "force", false,
		"Force overwritting existing public key",
	)
	return cmd
}

// LoadPrivate key loads a private key from file.
func LoadPrivateKey(filename string) (crypto.Signer, error) {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, serrors.WrapStr("reading private key", err)
	}
	p, rest := pem.Decode(raw)
	if p == nil {
		return nil, serrors.New("parsing private key failed")
	}
	if len(rest) != 0 {
		return nil, serrors.New("file must only contain private key")
	}
	if p.Type != "PRIVATE KEY" {
		return nil, serrors.New("file does not contain a private key", "type", p.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, serrors.WrapStr("parsing private key", err)
	}

	priv, ok := key.(crypto.Signer)
	if !ok {
		return nil, serrors.New("cannot get public key from private key",
			"type", fmt.Sprintf("%T", priv),
		)
	}
	return priv, nil
}
