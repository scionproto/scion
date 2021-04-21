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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
)

func newVerifyCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		trcFile  string
		unixTime int64
	}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a certificate chain",
		Long: `'verify' verifies the certificate chains based on a trusted TRC.

The chain must be a PEM bundle with the AS certificate first, and the CA
certificate second.
`,
		Example: fmt.Sprintf(`  %[1]s verify --trc ISD1-B1-S1.trc ISD1-ASff00_0_110.pem`,
			pather.CommandPath()),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			chain, err := cppki.ReadPEMCerts(args[0])
			if err != nil {
				return serrors.WrapStr("reading chain", err, "file", args[0])
			}
			trc, err := loadTRC(flags.trcFile)
			if err != nil {
				return err
			}

			opts := cppki.VerifyOptions{TRC: &trc.TRC}
			if flags.unixTime != 0 {
				opts.CurrentTime = time.Unix(flags.unixTime, 0)
			}

			if err := cppki.VerifyChain(chain, opts); err != nil {
				return serrors.WrapStr("verification failed", err)
			}

			fmt.Printf("Successfully verified certificate chain: %q\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.trcFile, "trc", "", "trusted TRC (required)")
	cmd.Flags().Int64Var(&flags.unixTime, "currenttime", 0,
		"Optional unix timestamp that sets the current time")
	cmd.MarkFlagRequired("trc")

	joined := command.Join(pather, cmd)
	cmd.AddCommand(newVerifyCACmd(joined))

	return cmd
}

func newVerifyCACmd(pather command.Pather) *cobra.Command {
	var flags struct {
		trcFile  string
		unixTime int64
	}

	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Verify a CA certificate",
		Long: `'ca' verifies the CA certificate based on a trusted TRC.

The CA certificate must be a PEM encoded.
`,
		Example: fmt.Sprintf(`  %[1]s --trc ISD1-B1-S1.trc ISD1-ASff00_0_110.ca.crt`,
			pather.CommandPath()),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			certs, err := cppki.ReadPEMCerts(args[0])
			if err != nil {
				return serrors.WrapStr("reading certificate", err, "file", args[0])
			}
			if len(certs) != 1 {
				return serrors.New("file contains multiple certificates", "count", len(certs))
			}
			ct, err := cppki.ValidateCert(certs[0])
			if err != nil {
				return serrors.WrapStr("validating CA certificate", err)
			}
			if ct != cppki.CA {
				return serrors.New("certificate of wrong type", "type", ct)
			}

			trc, err := loadTRC(flags.trcFile)
			if err != nil {
				return err
			}
			rootPool, err := trc.TRC.RootPool()
			if err != nil {
				return serrors.WrapStr("failed to extract root certificates from TRC", err)
			}
			var currTime time.Time
			if flags.unixTime != 0 {
				currTime = time.Unix(flags.unixTime, 0)
			}
			_, err = certs[0].Verify(x509.VerifyOptions{
				Roots:       rootPool,
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
				CurrentTime: currTime,
			})
			if err != nil {
				return serrors.WrapStr("verification failed", err)
			}

			fmt.Printf("Successfully verified CA certificate: %q\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.trcFile, "trc", "", "trusted TRC (required)")
	cmd.Flags().Int64Var(&flags.unixTime, "currenttime", 0,
		"Optional unix timestamp that sets the current time")
	cmd.MarkFlagRequired("trc")

	return cmd
}

func loadTRC(trcFile string) (cppki.SignedTRC, error) {
	raw, err := ioutil.ReadFile(trcFile)
	block, _ := pem.Decode(raw)
	if block != nil && block.Type == "TRC" {
		raw = block.Bytes
	}
	if err != nil {
		return cppki.SignedTRC{}, serrors.WrapStr("reading TRC", err, "file", trcFile)
	}
	return cppki.DecodeSignedTRC(raw)
}
