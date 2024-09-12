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

package certs

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	scionpki "github.com/scionproto/scion/scion-pki"
	"github.com/scionproto/scion/scion-pki/key"
)

func newMatchCmd(pather command.Pather) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "match",
		Short: "Match the certificate with other trust objects",
	}
	joined := command.Join(pather, cmd)

	cmd.AddCommand(
		newMatchPrivateKey(joined),
	)
	return cmd
}

func newMatchPrivateKey(pather command.Pather) *cobra.Command {
	var flags struct {
		separator string
		kms       string
	}
	cmd := &cobra.Command{
		Use:   "private <certificate> <private-key> [<private-key> ...]",
		Short: "Find the matching private keys for the certificate",
		Long: `'private' finds all the matching private keys for the certificate.
If the file contains a certificate chain, only the keys authenticated by the first
certificate in the chain are considered.

The output contains all the private keys that are authenticated by the certificate.
`,
		Example: fmt.Sprintf(`  %[1]s private ISD1-ASff00_0_110.pem cp-as.key
  %[1]s private ISD1-ASff00_0_110.pem *.key`,
			pather.CommandPath(),
		),
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			certs, err := cppki.ReadPEMCerts(args[0])
			if err != nil {
				return serrors.Wrap("parsing certificate", err, "file", args[0])
			}
			certKey, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
			if err != nil {
				return serrors.Wrap("packing the certificate public key", err)
			}

			var keys []string
			for _, file := range args[1:] {
				key, err := loadPackedPublicFromPrivate(flags.kms, file)
				if err != nil {
					fmt.Fprintf(os.Stderr, "WARN: ignoring %q: %s\n", file, err)
					continue
				}
				if !bytes.Equal(certKey, key) {
					continue
				}
				keys = append(keys, file)
			}
			if len(keys) == 0 {
				return serrors.New("no matching private key found")
			}
			fmt.Println(strings.Join(keys, flags.separator))
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.separator, "separator", "\n", "The separator between file names")
	scionpki.BindFlagKms(cmd.Flags(), &flags.kms)
	return cmd
}

func loadPackedPublicFromPrivate(kms, name string) ([]byte, error) {
	key, err := key.LoadPrivateKey(kms, name)
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, serrors.Wrap("packing the public key", err)
	}
	return pub, nil
}
