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
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
)

func newExtract(pather command.Pather) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Extract parts of a signed TRC",
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

To inspect the created asn.1 file you can use the openssl tool::

 openssl asn1parse -inform DER -i -in payload.der

(for more information see 'man asn1parse')
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			signed, err := DecodeFromFile(args[0])
			if err != nil {
				return serrors.Wrap("failed to load signed TRC", err)
			}
			raw := signed.TRC.Raw
			if flags.format == "pem" {
				raw = pem.EncodeToMemory(&pem.Block{
					Type:  "TRC PAYLOAD",
					Bytes: raw,
				})
			}
			if err := os.WriteFile(flags.out, raw, 0o644); err != nil {
				return serrors.Wrap("failed to write extracted payload", err)
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
		out   string
		ias   []string
		types []string
	}

	cmd := &cobra.Command{
		Use:     "certificates",
		Aliases: []string{"certs", "certificate", "cert"},
		Short:   "Extract the bundled certificates",
		Example: fmt.Sprintf(`  %[1]s certificates -o bundle.pem input.trc`, pather.CommandPath()),
		Long:    `'certificates' extracts the certificates into a bundled PEM file.`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			types := make(map[cppki.CertType]bool)
			for _, t := range flags.types {
				if t == "any" {
					types = nil // No filter, all types are included.
					break
				}
				typ, ok := certTypes[t]
				if !ok {
					return fmt.Errorf("unknown certificate type %q, valid types are: %s",
						t, strings.Join(getTypes(), ", "))
				}
				types[typ] = true
			}

			ias := make(map[addr.IA]bool)
			for _, v := range flags.ias {
				ia, err := addr.ParseIA(v)
				if err != nil {
					return fmt.Errorf("invalid ISD-AS %q: %w", v, err)
				}
				ias[ia] = true
			}

			cmd.SilenceUsage = true

			if err := runExtractCertificates(args[0], flags.out, types, ias); err != nil {
				return err
			}
			if flags.out != "" && flags.out != "-" {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"Successfully extracted certificates at %s\n", flags.out)
			}
			return nil
		},
	}

	addOptionalOutputFlag(&flags.out, cmd)

	cmd.Flags().StringSliceVar(&flags.ias, "subject.isd-as", nil,
		"Filter certificates by ISD-AS of the subject (e.g., 1-ff00:0:110)")
	cmd.Flags().StringSliceVar(&flags.types, "type", nil,
		"Filter certificates by type ("+strings.Join(getTypes(), "|")+")")
	return cmd
}

func runExtractCertificates(
	in, out string, types map[cppki.CertType]bool, ias map[addr.IA]bool,
) error {
	signed, err := DecodeFromFile(in)
	if err != nil {
		return serrors.Wrap("failed to load signed TRC", err)
	}
	certs := make([]*x509.Certificate, 0, len(signed.TRC.Certificates))

	// Filter the certificates based on the user input.
	for _, cert := range signed.TRC.Certificates {
		// Check certificate type
		{
			typ, err := cppki.ValidateCert(cert)
			if err != nil {
				return fmt.Errorf("invalid certificate %s: %w", cert.Subject.CommonName, err)
			}
			if len(types) > 0 && !types[typ] {
				continue
			}
		}

		// Check certificate ISD-AS
		{
			ia, err := cppki.ExtractIA(cert.Subject)
			if err != nil {
				return fmt.Errorf("failed to extract ISD-AS from certificate %s: %w",
					cert.Subject.CommonName, err)
			}
			if len(ias) > 0 && !ias[ia] {
				continue
			}
		}
		certs = append(certs, cert)
	}

	return writeBundle(out, certs)
}

func writeBundle(out string, certs []*x509.Certificate) error {
	o := os.Stdout
	if out != "" && out != "-" {
		var err error
		if o, err = os.Create(out); err != nil {
			return serrors.Wrap("unable to create file", err)
		}
		defer o.Close()
	}
	for i, cert := range certs {
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := pem.Encode(o, &block); err != nil {
			return serrors.Wrap("unable to encode certificate", err, "index", i)
		}
	}
	return nil
}

var certTypes = map[string]cppki.CertType{
	cppki.Root.String():      cppki.Root,
	cppki.CA.String():        cppki.CA,
	cppki.AS.String():        cppki.AS,
	cppki.Sensitive.String(): cppki.Sensitive,
	cppki.Regular.String():   cppki.Regular,
}

func getTypes() []string {
	options := make([]string, 0, len(certTypes)+1)
	for k := range certTypes {
		options = append(options, k)
	}
	options = append(options, "any")
	slices.Sort(options)
	return options
}
