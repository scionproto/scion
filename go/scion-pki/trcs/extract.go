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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
)

func newExtract(pather command.Pather) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Exctract parts of a signed TRC",
	}
	joined := command.Join(pather, cmd)
	cmd.AddCommand(
		newExtractPayload(joined),
		newExtractCertificates(joined),
	)
	return cmd
}

func newExtractPayload(pather command.Pather) *cobra.Command {
	var flags struct {
		out    string
		format string
	}

	cmd := &cobra.Command{
		Use:     "payload",
		Aliases: []string{"pld"},
		Short:   "Extract the TRC payload",
		Example: fmt.Sprintf(`  %[1]s payload -o payload.der input.trc`, pather.CommandPath()),
		Long: `'payload' extracts the asn.1 encoded DER TRC payload.

To inspect the created asn.1 file you can use the openssl tool:

  openssl asn1parse -inform DER -i -in payload.der
  (for more information see 'man asn1parse')
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			signed, err := DecodeFromFile(args[0])
			if err != nil {
				return serrors.WrapStr("failed to load signed TRC", err)
			}
			raw := signed.TRC.Raw
			if flags.format == "pem" {
				raw = pem.EncodeToMemory(&pem.Block{
					Type:  "TRC PAYLOAD",
					Bytes: raw,
				})
			}
			if err := ioutil.WriteFile(flags.out, raw, 0644); err != nil {
				return serrors.WrapStr("failed to write extracted payload", err)
			}
			fmt.Printf("Successfully extracted payload at %s\n", flags.out)
			return nil
		},
	}

	addOutputFlag(&flags.out, cmd)
	cmd.Flags().StringVar(&flags.format, "format", "der", "Output format (der|pem)")
	return cmd
}

func newExtractCertificates(pather command.Pather) *cobra.Command {
	var flags struct {
		out string
	}

	cmd := &cobra.Command{
		Use:     "certificates",
		Aliases: []string{"certs"},
		Short:   "Extract the bundled certificates",
		Example: fmt.Sprintf(`  %[1]s certificates -o bundle.pem input.trc`, pather.CommandPath()),
		Long:    `'certificates' extracts the certificates into a bundeld PEM file.`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runExtractCertificates(args[0], flags.out); err != nil {
				return err
			}
			fmt.Printf("Successfully extracted certificates at %s\n", flags.out)
			return nil
		},
	}

	addOutputFlag(&flags.out, cmd)
	return cmd
}

func runExtractCertificates(in, out string) error {
	signed, err := DecodeFromFile(in)
	if err != nil {
		return serrors.WrapStr("failed to load signed TRC", err)
	}
	return writeBundle(out, signed.TRC.Certificates)
}

func writeBundle(out string, certs []*x509.Certificate) error {
	file, err := os.Create(out)
	if err != nil {
		return serrors.WrapStr("unable to create file", err)
	}
	defer file.Close()
	for i, cert := range certs {
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := pem.Encode(file, &block); err != nil {
			return serrors.WrapStr("unable to encode certificate", err, "index", i)
		}
	}
	return nil
}
