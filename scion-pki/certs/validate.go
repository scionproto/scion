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

package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/app/flag"
)

func newValidateCmd(pather command.Pather) *cobra.Command {
	now := time.Now()
	var flags struct {
		certType    string
		checkTime   bool
		currentTime flag.Time
	}
	flags.currentTime = flag.Time{
		Time:    now,
		Current: now,
	}
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a SCION cert according to its type",
		Long: `'validate' checks if the certificate is valid and of the specified type.

In case the 'any' type is specified, this command attempts to identify what type
a certificate is and validates it accordingly. The identified type is stated in
the output.

By default, the command does not check that the certificate is in its validity
period. This can be enabled by specifying the \--check-time flag.
`,
		Example: fmt.Sprintf(`  %[1]s validate --type cp-root /tmp/certs/cp-root.crt
  %[1]s validate --type any /tmp/certs/cp-root.crt`, pather.CommandPath()),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			expectedType, checkType := certTypes[flags.certType]
			if !checkType && (flags.certType != "any" && flags.certType != "chain") {
				return serrors.New("invalid type flag", "type", flags.certType)
			}
			cmd.SilenceUsage = true

			filename := args[0]
			certs, err := cppki.ReadPEMCerts(filename)
			if err != nil {
				return err
			}
			if flags.checkTime {
				validity := cppki.Validity{
					NotBefore: certs[0].NotBefore,
					NotAfter:  certs[0].NotAfter,
				}
				if current := flags.currentTime.Time; !validity.Contains(current) {
					return app.WithExitCode(
						serrors.New("time not covered by certificate",
							"current_time", current,
							"validity.not_before", validity.NotBefore,
							"validity.not_after", validity.NotAfter,
						),
						99,
					)
				}
			}
			if flags.certType == "chain" || len(certs) != 1 && flags.certType == "any" {
				if err := validateChain(certs); err != nil {
					return err
				}
				fmt.Printf("Valid certificate chain: %q\n", filename)

			} else {
				ct, err := validateCert(certs, expectedType, checkType)
				if err != nil {
					return err
				}
				fmt.Printf("Valid %s certificate: %q\n", ct, filename)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.certType, "type", "",
		fmt.Sprintf("type of cert (%s) (required)", strings.Join(getTypes(), "|")),
	)
	cmd.Flags().BoolVar(&flags.checkTime, "check-time", false,
		"Check that the certificate covers the current time.",
	)
	cmd.Flags().Var(&flags.currentTime, "current-time",
		`The time that needs to be covered by the certificate.
Can either be a timestamp or an offset.

If the value is a timestamp, it is expected to either be an RFC 3339 formatted
timestamp or a unix timestamp. If the value is a duration, it is used as the
offset from the current time.`,
	)
	cmd.MarkFlagRequired("type")

	return cmd
}

func validateChain(certs []*x509.Certificate) error {
	if err := cppki.ValidateChain(certs); err != nil {
		return err
	}
	checkAlgorithm(certs[0])
	checkAlgorithm(certs[1])
	return nil
}

func validateCert(
	certs []*x509.Certificate,
	expectedType cppki.CertType,
	checkType bool,
) (cppki.CertType, error) {

	if len(certs) != 1 {
		return cppki.Invalid, serrors.New("file with multiple certificates not supported")
	}
	cert := certs[0]
	ct, err := cppki.ValidateCert(cert)
	if err != nil {
		return cppki.Invalid, err
	}
	if checkType && expectedType != ct {
		return cppki.Invalid, serrors.New("wrong certificate type",
			"expected", expectedType,
			"actual", ct,
		)
	}
	if ct == cppki.Root || ct == cppki.Regular || ct == cppki.Sensitive {
		checkAlgorithm(cert)
	}
	return ct, nil
}

func checkAlgorithm(cert *x509.Certificate) {
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return
	}
	expected := map[elliptic.Curve]x509.SignatureAlgorithm{
		elliptic.P256(): x509.ECDSAWithSHA256,
		elliptic.P384(): x509.ECDSAWithSHA384,
		elliptic.P521(): x509.ECDSAWithSHA512,
	}[pub.Curve]
	if expected != cert.SignatureAlgorithm {
		fmt.Printf("WARNING: Signature with %s curve should use %s instead of %s\n",
			pub.Curve.Params().Name, expected, cert.SignatureAlgorithm)
	}
}
