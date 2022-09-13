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
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/encoding"
)

func newFingerprintCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		format string
	}

	var cmd = &cobra.Command{
		Use:   "fingerprint [flags] <cert-file>",
		Short: "Calculate the SHA256 fingerprint of a certificate or certificate chain",
		Long: `'fingerprint' computes the SHA256 fingerprint of the raw certificate or
certificate chain.

If 'cert-file' contains a single certificate, the SHA256 is computed over the raw
DER encoding. If it contains a certificate chain, the SHA256 is computed over the
concatenation of the raw DER encoding of the certificates in order of appearance.

If the flag \--format is set to "emoji", the format of the output is a string of emojis`,
		Example: fmt.Sprintf(`  %[1]s fingerprint ISD1-ASff00_0_110.pem
  %[1]s fingerprint --format emoji ISD1-ASff00_0_110.pem
  %[1]s fingerprint --format hex ISD1-ASff00_0_110.pem
		`, pather.CommandPath()),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			if flags.format != "hex" && flags.format != "emoji" {
				return serrors.New("format not supported", "format", flags.format)
			}
			cmd.SilenceUsage = true

			chain, err := cppki.ReadPEMCerts(args[0])
			if err != nil {
				return serrors.WrapStr("loading certificate chain", err)
			}

			h := sha256.New()
			for i := range chain {
				h.Write(chain[i].Raw)
			}
			fingerprint := h.Sum(nil)
			var output string
			if flags.format == "emoji" {
				output = encoding.ToEmoji(fingerprint)
			} else {
				output = hex.EncodeToString(fingerprint)
			}

			outputWriter := cmd.OutOrStdout()
			fmt.Fprintln(outputWriter, output)

			return nil
		},
	}

	cmd.Flags().StringVar(&flags.format, "format", "hex",
		"Specify the format of the fingerprint to an string of hex or emoji characters",
	)

	return cmd
}
