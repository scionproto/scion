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

// Package certs provides a generator for AS-level certs involved in the SCION
// control plane PKI.
package certs

import (
	"fmt"
	"os"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var CmdCerts = &base.Command{
	Name:      "certs",
	Run:       runCert,
	UsageLine: "certs [-h] (gen|renew|template|verify|clean) [<flags>] [<selector>|<files>]",
	Short:     "Generate and renew certificate chains for the SCION control plane PKI.",
	Long: `
'certs' can be used to generate and renew certificate chains for the SCION control plane PKI.

Subcommands:
	gen
		Used to generate new certificates.
	renew (NOT IMPLEMENTED)
		Used to renew existing certificates.
	template
		Used to generate as.ini (core-as.ini if -core supplied) template configuration files.
	clean (NOT IMPLEMENTED)
		Used to clean the PKI root directory.

Flags:
	-d
		The root directory of all certificates and keys (default '.')
	-f
		Overwrite existing certificates (and keys if -genkeys is specified).
	-verify (default TRUE)
		Also verify the generated/renewed certificates.

Selector:
	*-*
		All ISDs and ASes under the root directory.
	X-*
		All ASes in ISD X.
	X-Y
		A specific AS X-Y, e.g. AS 1-11

'certs' needs to be pointed to the root directory where all keys and certificates are
stored on disk (-d flag). It expects the contents of the root directory to follow
a predefined structure:
	<root>/
		ISD1/
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
the certificates. It follows the ini format and has a top-level attribute "core = (true|false)"
that indicates whether this AS is a core AS or not. Furthermore, as.ini must contain a 
"AS Certificate" section and in case of core==true also a "Core AS Certificate" section
that can contain the following values:
	Subject [required]
		string representing the entity that owns the certificate and the corresponding
		key pair. An AS is represented as a string ISD-AS (e.g., 1-11).
	Issuer [required]
		string identifying the entity that signed the certificate. An AS is represented
		as a string ISD-AS (e.g., 1-11).
	TRCVersion [required]
		integer representing the version of TRC that the issuer used at the time of
		signing the certificate.
	Version [required]
		integer representing the version of the certificate
	Comment [optional]
		arbitrary string used to describe the certificate
	CanIssue [required]
		boolean that describes whether the subject is allowed to issue
		certificates for other ASes
	Validity [required]
		the validity of the certificate in days
	IssuingTime (now) [optional]
		the time the certificate was issued as a UNIX timestamp
	EncAlgorithm (curve25519xalsa20poly1305) [optional]
		cryptographic algorithm that must be used to encrypt/decrypt a message
		with the subject’s public/private key
	SignAlgorithm (ed25519) [optional]
		cryptographic algorithm that must be used to sign/verify a message with
		the subject’s private/public key.
`,
}

var (
	genKeys bool
	core    bool
	verify  bool
)

func init() {
	CmdCerts.Flag.StringVar(&pkicmn.RootDir, "d", ".", "")
	CmdCerts.Flag.BoolVar(&pkicmn.Force, "f", false, "")
	CmdCerts.Flag.BoolVar(&genKeys, "genkeys", false, "")
	CmdCerts.Flag.BoolVar(&core, "core", false, "")
	CmdCerts.Flag.BoolVar(&verify, "verify", true, "")
}

func runCert(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	subCmd := args[0]
	cmd.Flag.Parse(args[1:])
	switch subCmd {
	case "gen":
		runGenCert(cmd, cmd.Flag.Args())
	case "renew":
		fmt.Println("renew is not implemented yet.")
		return
	case "template":
		runTemplate(cmd, cmd.Flag.Args())
	case "verify":
		runVerify(cmd, cmd.Flag.Args())
	case "clean":
		fmt.Println("clean is not implemented yet.")
		return
	default:
		fmt.Fprintf(os.Stderr, "unrecognized subcommand '%s'\n", args[0])
		fmt.Fprintf(os.Stderr, "run 'scion-pki certs -h' for help.\n")
		os.Exit(2)
	}
}
