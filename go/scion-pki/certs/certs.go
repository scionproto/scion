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
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
)

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
	sort.Strings(options)
	return options
}

func Cmd(pather command.Pather) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certs",
		Short: "Interact with certificates for the SCION control plane PKI.",
	}
	joined := command.Join(pather, cmd)
	cmd.AddCommand(
		newValidateCmd(joined),
		newVerifyCmd(joined),
		newRenewCmd(joined),
	)
	return cmd
}

func newValidateCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		certType string
	}

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a SCION cert according to its type",
		Long: `'validate' checks if the certificate is valid and of the specified type.

In case the 'any' type is specified, this command attempts to identify what type
a certificate is and validates it accordingly. The identified type is stated in
the output.
`,
		Example: fmt.Sprintf(`  %[1]s validate --type cp-root /tmp/certs/cp-root.crt
  %[1]s validate --type any /tmp/certs/cp-root.crt`, pather.CommandPath()),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			expectedType, checkType := certTypes[flags.certType]
			if !checkType && flags.certType != "any" {
				return serrors.New("invalid type flag", "type", flags.certType)
			}
			cmd.SilenceUsage = true
			return runValidate(args[0], expectedType, checkType)
		},
	}

	cmd.Flags().StringVar(&flags.certType, "type", "",
		fmt.Sprintf("type of cert (%s) (required)", strings.Join(getTypes(), "|")))
	cmd.MarkFlagRequired("type")

	return cmd
}

func runValidate(path string, expectedType cppki.CertType, checkType bool) error {
	certs, err := cppki.ReadPEMCerts(path)
	if err != nil {
		return err
	}
	if len(certs) > 1 {
		return serrors.New("file with multiple certificates not supported")
	}
	cert := certs[0]
	ct, err := cppki.ValidateCert(cert)
	if err != nil {
		return err
	}
	if checkType && expectedType != ct {
		return serrors.New("wrong certificate type", "expected", expectedType, "actual", ct)
	}
	if ct == cppki.Root || ct == cppki.Regular || ct == cppki.Sensitive {
		checkAlgorithm(cert)
	}
	fmt.Printf("Valid %s certificate: %q\n", ct, path)
	return nil
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
