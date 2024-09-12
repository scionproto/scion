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
)

func newMatchCmd(pather command.Pather) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "match",
		Short: "Match the key with other trust objects",
	}
	joined := command.Join(pather, cmd)

	cmd.AddCommand(
		newMatchCertificate(joined),
	)
	return cmd
}

func newMatchCertificate(pather command.Pather) *cobra.Command {
	var flags struct {
		separator string
		kms       string
	}
	cmd := &cobra.Command{
		Use:   "certificate <private-key> <certificate> [<certificate> ...]",
		Short: "Find the matching certificate for the key",
		Long: `'certificate' finds all the matching certificates for the key.
If a file contains a certificate chain, only the first certificate in the chain
is considered.

The output contains all certificates that authenticate the key.
`,
		Example: fmt.Sprintf(`  %[1]s certificate cp-as.key ISD1-ASff00_0_110.pem
  %[1]s certificate cp-as.key *.pem`,
			pather.CommandPath(),
		),
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			key, err := LoadPrivateKey(flags.kms, args[0])
			if err != nil {
				return err
			}
			pub, err := x509.MarshalPKIXPublicKey(key.Public())
			if err != nil {
				return serrors.Wrap("packing the public key", err)
			}

			var certificates []string
			for _, file := range args[1:] {
				key, err := loadPackedPublicFromCertificate(file)
				if err != nil {
					fmt.Fprintf(os.Stderr, "WARN: ignoring %q: %s\n", file, err)
					continue
				}
				if !bytes.Equal(pub, key) {
					continue
				}
				certificates = append(certificates, file)
			}
			if len(certificates) == 0 {
				return serrors.New("no matching certificate found")
			}
			fmt.Println(strings.Join(certificates, flags.separator))
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.separator, "separator", "\n", "The separator between file names")
	scionpki.BindFlagKms(cmd.Flags(), &flags.kms)
	return cmd
}

func loadPackedPublicFromCertificate(file string) ([]byte, error) {
	certs, err := cppki.ReadPEMCerts(file)
	if err != nil {
		return nil, serrors.Wrap("parsing certificate", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
	if err != nil {
		return nil, serrors.Wrap("packing the public key", err)
	}
	return pub, nil
}
