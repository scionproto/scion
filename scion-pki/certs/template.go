// Copyright 2025 Anapaya Systems
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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	"github.com/spf13/cobra"
)

func newTemplateCmd(_ command.Pather) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Create subject template from a certificate or CSR",
		Long: `'template' creates a subject template from a certificate, certificate chain, or CSR.

This command allows reconstructing the subject template that was used to cerate a certificate
or a certificate signing request (CSR). It is not necessary to use this command to create a
new certificate or CSR, as the template to the 'create' command can also be a certificate
itself.

In case the input is a certificate chain, the template is created from the first certificate
in the chain.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			subject, err := loadPkixNameFromFile(args[0])
			if err != nil {
				return fmt.Errorf("loading subject from file %q: %w", args[0], err)
			}

			ia, err := cppki.ExtractIA(subject)
			if err != nil {
				return fmt.Errorf("extracting ISD-AS from certificate: %w", err)
			}

			maybe := func(v []string) string {
				if len(v) == 0 {
					return ""
				}
				return v[0]
			}
			vars := SubjectVars{
				IA:                 ia,
				CommonName:         subject.CommonName,
				Organization:       maybe(subject.Organization),
				Country:            maybe(subject.Country),
				Province:           maybe(subject.Province),
				Locality:           maybe(subject.Locality),
				OrganizationalUnit: maybe(subject.OrganizationalUnit),
				PostalCode:         maybe(subject.PostalCode),
				StreetAddress:      maybe(subject.StreetAddress),
				SerialNumber:       subject.SerialNumber,
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(vars); err != nil {
				return fmt.Errorf("encoding template: %w", err)
			}
			return nil
		},
	}
	return cmd
}

func loadPkixNameFromFile(filename string) (pkix.Name, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return pkix.Name{}, fmt.Errorf("reading file %q: %w", filename, err)
	}
	return loadPkixNameFromRaw(raw)
}

func loadPkixNameFromRaw(raw []byte) (pkix.Name, error) {
	pemData, _ := pem.Decode(raw)
	if pemData == nil {
		return pkix.Name{}, fmt.Errorf("not valid PEM")
	}
	switch pemData.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(pemData.Bytes)
		if err != nil {
			return pkix.Name{}, fmt.Errorf("parsing certificate: %w", err)
		}
		return cert.Subject, nil
	case "CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(pemData.Bytes)
		if err != nil {
			return pkix.Name{}, fmt.Errorf("parsing CSR: %w", err)
		}
		return csr.Subject, nil
	default:
		return pkix.Name{}, fmt.Errorf("invalid PEM block type %q", pemData.Type)
	}
}
