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
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
)

func newVerifyCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		trcFiles []string
		unixTime int64
	}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a certificate chain",
		Long: `'verify' verifies the certificate chains based on a trusted TRC.

The chain must be a PEM bundle with the AS certificate first, and the CA
certificate second.
`,
		Example: fmt.Sprintf(
			`  %[1]s verify --trc ISD1-B1-S1.trc,ISD1-B1-S2.trc ISD1-ASff00_0_110.pem`,
			pather.CommandPath(),
		),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			chain, err := cppki.ReadPEMCerts(args[0])
			if err != nil {
				return serrors.WrapStr("reading chain", err, "file", args[0])
			}
			trcs, err := loadTRCs(flags.trcFiles)
			if err != nil {
				return err
			}

			if flags.unixTime != 0 && len(flags.trcFiles) != 1 {
				return serrors.New("seelcting TRC for specific time is not supported yet.")
			}

			opts := cppki.VerifyOptions{TRC: trcs}
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

	cmd.Flags().StringSliceVar(&flags.trcFiles, "trc", []string{},
		"Comma-separated trusted TRCs. If more than two TRCs are specified, only up to "+
			"two active TRCs with the highest Base version are used (required)")
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

// loadTRCs is a helper function to load the two latest TRCs from files. If any
// file cannot be read, a nil slice is returned and an error.
func loadTRCs(trcFiles []string) ([]*cppki.TRC, error) {
	var signedTRCs []cppki.SignedTRC
	for _, trcFile := range trcFiles {
		signedTRC, err := loadTRC(trcFile)
		if err != nil {
			return nil, serrors.WrapStr("loading from disk", err)
		}
		signedTRCs = append(signedTRCs, signedTRC)
	}

	latestSignedTRCs, err := selectLatestTRCs(signedTRCs)
	if err != nil {
		return nil, serrors.WrapStr("selecting latest TRCs", err)
	}
	return trcSlice(latestSignedTRCs), nil
}

// selectLatestTRCs selects the latest two TRCs by finding the highest base
// number, and then out of that set selecting up to two TRCs with the highest
// serial number. The higher serial number TRC is returned first in the list.
// If the serial numbers are not consecutive, only the TRC with the higher serial
// number is returned. If the predecessor TRC is not active anymore (due to grace period
// constraints) only the TRC with the higher serial number is returned.
// The behavior is undefined if the TRCs belong to different ISDs.
//
// The elements of the returned slice are shallow copies of the elements in the input.
//
// If the length of the input slice is 0, an error is returned.
func selectLatestTRCs(trcs []cppki.SignedTRC) ([]cppki.SignedTRC, error) {
	if len(trcs) == 0 {
		return nil, serrors.New("no TRCs in slice")
	}

	if len(trcs) == 1 {
		return []cppki.SignedTRC{trcs[0]}, nil
	}

	// copy the slice contents to avoid mutating the arg
	var copyTRCs []cppki.SignedTRC
	for _, v := range trcs {
		copyTRCs = append(copyTRCs, v)
	}

	// Sort according to Greater than, s.t. the highest values are at the start of the slice
	sort.Slice(copyTRCs, func(i, j int) bool {
		if copyTRCs[i].TRC.ID.Base != copyTRCs[j].TRC.ID.Base {
			return copyTRCs[i].TRC.ID.Base > copyTRCs[j].TRC.ID.Base
		}
		return copyTRCs[i].TRC.ID.Serial > copyTRCs[j].TRC.ID.Serial
	})
	// If the two latest TRCs have different base versions, choose only the latest one.
	if copyTRCs[0].TRC.ID.Base != copyTRCs[1].TRC.ID.Base {
		return []cppki.SignedTRC{copyTRCs[0]}, nil
	}
	if copyTRCs[0].TRC.ID.Serial != copyTRCs[1].TRC.ID.Serial+1 {
		return []cppki.SignedTRC{copyTRCs[0]}, nil
	}
	if !copyTRCs[0].TRC.InGracePeriod(time.Now()) {
		return []cppki.SignedTRC{copyTRCs[0]}, nil
	}
	return []cppki.SignedTRC{copyTRCs[0], copyTRCs[1]}, nil
}

func trcSlice(signedTRCs []cppki.SignedTRC) []*cppki.TRC {
	var trcs []*cppki.TRC
	for i := range signedTRCs {
		trcs = append(trcs, &signedTRCs[i].TRC)
	}
	return trcs
}
