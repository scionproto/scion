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
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/app/flag"
	scionpki "github.com/scionproto/scion/scion-pki"
	"github.com/scionproto/scion/scion-pki/key"
)

// newSignCmd returns a cobra command that signs certificates based on a CSR.
func newSignCmd(pather command.Pather) *cobra.Command {
	now := time.Now().UTC()
	var flags struct {
		profile   string
		notBefore flag.Time
		notAfter  flag.Time
		ca        string
		caKey     string
		caKms     string
		bundle    bool
	}
	flags.notBefore = flag.Time{
		Time:    now,
		Current: now,
	}
	flags.notAfter = flag.Time{
		Current: now,
		Default: "depends on profile",
	}

	var cmd = &cobra.Command{
		Use:   "sign [flags] <csr-file>",
		Short: "Sign a certificate based on a certificate signing request",
		Example: fmt.Sprintf(`  %[1]s sign --ca cp-ca.crt --ca-key cp-ca.key cp-as.csr
  %[1]s sign --profile cp-ca --ca cp-root.crt --ca-key cp-root.key cp-ca.csr `,
			pather.CommandPath(),
		),
		Long: `'sign' creates a certificate based on a certificate signing request (CSR).

The command takes the following positional arguments:

- <csr-file> is the file path where the PEM-encoded certificate signing request is located.

By default, the command creates a SCION control-plane PKI AS certificate. Another
certificate type can be selected by providing the \--profile flag. If a certificate
chain is desired, specify the \--bundle flag.

The \--ca and \--ca-key flags are required.

The \--not-before and \--not-after flags can either be a timestamp or a relative
time offset from the current time.

A timestamp can be provided in two different formats: unix timestamp and
RFC 3339 timestamp. For example, 2021-06-24T12:01:02Z represents 1 minute and 2
seconds after the 12th hour of June 26th, 2021 in UTC.

The relative time offset can be formated as a time duration string with the
following units: y, w, d, h, m, s. Negative offsets are also allowed. For
example, -1h indicates the time of tool invocation minus one hour. Note that
\--not-after is relative to the current time if a relative time offset is used,
and not to \--not-before.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ct, err := parseCertType(flags.profile)
			if err != nil {
				return serrors.Wrap("parsing profile", err)
			}
			if ct != cppki.AS && ct != cppki.CA {
				return serrors.New("not supported", "profile", flags.profile)
			}

			cmd.SilenceUsage = true

			csrRaw, err := os.ReadFile(args[0])
			if err != nil {
				return serrors.Wrap("loading CSR", err)
			}
			csrPem, rest := pem.Decode(csrRaw)
			if len(rest) != 0 {
				return serrors.New("trailing bytes in CSR")
			}
			csr, err := x509.ParseCertificateRequest(csrPem.Bytes)
			if err != nil {
				return serrors.Wrap("parsing CSR", err)
			}

			caCertRaw, err := os.ReadFile(flags.ca)
			if err != nil {
				return serrors.Wrap("read CA certificate", err)
			}
			caCert, err := parseCertificate(caCertRaw)
			if err != nil {
				return serrors.Wrap("parsing CA certificate", err)
			}
			caKey, err := key.LoadPrivateKey(flags.caKms, flags.caKey)
			if err != nil {
				return serrors.Wrap("loading CA private key", err)
			}
			if !key.IsX509Signer(caKey) {
				return serrors.New("the CA key cannot be used to create X.509 certificates",
					"type", fmt.Sprintf("%T", caKey),
				)
			}

			subject := csr.Subject
			subject.ExtraNames = csr.Subject.Names

			certRaw, err := CreateCertificate(CertParams{
				Type:      ct,
				Subject:   subject,
				PubKey:    csr.PublicKey,
				NotBefore: flags.notBefore.Time,
				NotAfter:  notAfterFromFlags(ct, flags.notBefore, flags.notAfter),
				CAKey:     caKey,
				CACert:    caCert,
			})
			if err != nil {
				return serrors.Wrap("creating certificate", err)
			}

			cert, err := x509.ParseCertificate(certRaw)
			if err != nil {
				return serrors.Wrap("parsing created certificate", err)
			}
			if gt, err := cppki.ValidateCert(cert); err != nil {
				return serrors.Wrap("validating created certificate", err)
			} else if gt != ct {
				return serrors.New("created certificate with wrong type",
					"expected", ct,
					"actual", gt,
				)
			}

			encodedCert := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certRaw,
			})
			if encodedCert == nil {
				panic("failed to encode CSR")
			}
			if flags.bundle {
				encodedCert = append(encodedCert, caCertRaw...)
			}
			fmt.Print(string(encodedCert))
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.profile, "profile", "cp-as",
		"The type of certificate to sign (cp-as|cp-ca)",
	)
	cmd.Flags().Var(&flags.notBefore, "not-before",
		`The NotBefore time of the certificate. Can either be a timestamp or an offset.

If the value is a timestamp, it is expected to either be an RFC 3339 formatted
timestamp or a unix timestamp. If the value is a duration, it is used as the
offset from the current time.`,
	)
	cmd.Flags().Var(&flags.notAfter, "not-after",
		`The NotAfter time of the certificate. Can either be a timestamp or an offset.

If the value is a timestamp, it is expected to either be an RFC 3339 formatted
timestamp or a unix timestamp. If the value is a duration, it is used as the
offset from the current time.`,
	)
	cmd.Flags().StringVar(&flags.ca, "ca", "",
		"The path to the issuer certificate",
	)
	cmd.Flags().StringVar(&flags.caKey, "ca-key", "",
		"The path to the issuer private key used to sign the new certificate",
	)
	cmd.Flags().BoolVar(&flags.bundle, "bundle", false,
		"Bundle the certificate with the issuer certificate as a certificate chain",
	)
	scionpki.BindFlagKmsCA(cmd.Flags(), &flags.caKms)
	cmd.MarkFlagRequired("ca")
	cmd.MarkFlagRequired("ca-key")

	return cmd
}
