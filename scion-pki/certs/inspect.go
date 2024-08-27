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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
)

func newInspectCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		short bool
	}

	cmd := &cobra.Command{
		Use:   "inspect [flags] <certificate-file|CSR-file>",
		Short: "Inspect a certificate or a certificate signing request",
		Long: `outputs the certificate chain or a certificat signing
request (CSR) in human readable format.`,
		Example: fmt.Sprintf(
			`  %[1]s inspect ISD1-ASff00_0_110.pem
  %[1]s inspect --short ISD1-ASff00_0_110.pem`,
			pather.CommandPath(),
		),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return serrors.Wrap("loading file", err)
			}
			pemData, rest := pem.Decode(raw)
			if pemData == nil {
				return serrors.New("file is no valid PEM")
			}
			// print output to injected outWriter during testing
			w := cmd.OutOrStdout()
			switch pemData.Type {
			case "CERTIFICATE":
				certs, err := cppki.ParsePEMCerts(raw)
				if err != nil {
					return err
				}
				return prettyPrintCertificate(w, certs, flags.short)
			case "CERTIFICATE REQUEST":
				if len(rest) != 0 {
					return serrors.New("trailing bytes in CSR")
				}
				csr, err := x509.ParseCertificateRequest(pemData.Bytes)
				if err != nil {
					return serrors.Wrap("parsing CSR", err)
				}
				return prettyPrintCSR(w, csr, flags.short)
			default:
				return serrors.New("invalid PEM block", "type", pemData.Type)
			}
		},
	}

	cmd.Flags().BoolVar(&flags.short, "short", false,
		"Print details of certificate or CSR in short format",
	)

	return cmd
}

// prettyPrintCertChain prints a chain of certificates in human readable format.
func prettyPrintCertificate(w io.Writer, certs []*x509.Certificate, short bool) error {
	format := certificateText
	if short {
		format = certificateShortText
	}
	for i, cert := range certs {
		info, err := format(cert)
		if err != nil {
			return serrors.Wrap("formatting certificate info", err, "index", i)
		}
		if _, err = fmt.Fprint(w, info); err != nil {
			return serrors.Wrap("writing certificate info", err, "index", i)
		}
	}
	return nil
}

// prettyPrintCSR prints a CSR in human readable format.
func prettyPrintCSR(w io.Writer, csr *x509.CertificateRequest, short bool) error {
	format := certificateRequestText
	if short {
		format = certificateRequestShortText
	}
	info, err := format(csr)
	if err != nil {
		return serrors.Wrap("formatting CSR info", err)
	}
	if _, err = fmt.Fprint(w, info); err != nil {
		return serrors.Wrap("writing CSR info", err)
	}
	return nil
}
