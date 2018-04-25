// Copyright 2018 ETH Zurich
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
	"fmt"

	"github.com/spf13/cobra"
)

var verify bool

var Cmd = &cobra.Command{
	Use:   "certs",
	Short: "Generate and renew certificate chains for the SCION control plane PKI.",
	Long: `
'certs' can be used to generate and renew certificate chains for the SCION control plane PKI.

Selector:
	*-*
		All ISDs and ASes under the root directory.
	X-*
		All ASes in ISD X.
	X-Y
		A specific AS X-Y, e.g. AS 1-ff00:0:300

'certs' needs to be pointed to the root directory where all keys and certificates are
stored on disk (-d flag). It expects the contents of the root directory to follow
a predefined structure:
	<root>/
		ISD1/
			isd.ini
			AS1/
				as.ini
				certs/
				keys/
			AS2/
			...
		ISD2/
			AS1/
			...
		...

as.ini contains the preconfigured parameters according to which 'certs' generates
the certificates. It follows the ini format and contains up to three sections:
"AS Certificate", "Issuer Certificate" (if also an issuer), "Key Algorithms" (if also a core).
The AS Certificate and Issuer Certificate sections can contain the following values:
	Issuer [required]
		string identifying the entity that signed the certificate. An AS is
		represented as a string ISD-AS (e.g., 1-ff00:0:300). This is only
		needed in the "AS Certificate" section.
	TRCVersion [required]
		integer representing the version of TRC that the issuer used at the time of
		signing the certificate.
	Version [required]
		integer representing the version of the certificate
	Comment [optional]
		arbitrary string used to describe the AS and certificate
	Validity [required]
		the validity of the certificate as a duration string, e.g., 180d or 36h
	IssuingTime (now) [optional]
		the time the certificate was issued as a UNIX timestamp
	EncAlgorithm (curve25519xalsa20poly1305) [optional]
		cryptographic algorithm that must be used to encrypt/decrypt a message
		with the subject’s public/private key
	SignAlgorithm (ed25519) [optional]
		cryptographic algorithm that must be used to sign/verify a message with
		the subject’s private/public key.
The Key Algorithms section that can contain following values
	Online (ed25519) [optional]
		cryptographic algorithm that must be used as signing algorithm by online key
	Offline (ed25519) [optional]
		cryptographic algorithm that must be used as signing algorithm by offline key
`,
}

var genCerts = &cobra.Command{
	Use:   "gen",
	Short: "Generate new certificates",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runGenCert(args)
	},
}

var renewCerts = &cobra.Command{
	Use:   "renew",
	Short: "Renew the existing certificates [NOT IMPLEMENTED]",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("renew is not implemented yet")
	},
}

var cleanCerts = &cobra.Command{
	Use:   "clean",
	Short: "Clean all the exisiting certificates. [NOT IMPLEMENTED]",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("clean is not implemented yet")
	},
}

var verifyCert = &cobra.Command{
	Use:   "verify",
	Short: "Verify certificate for given selector",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runVerify(args)
	},
}

func init() {
	Cmd.PersistentFlags().BoolVarP(&verify, "verify", "v", true,
		"verify the generated/renewed certificates")
	Cmd.AddCommand(genCerts)
	Cmd.AddCommand(renewCerts)
	Cmd.AddCommand(cleanCerts)
}
