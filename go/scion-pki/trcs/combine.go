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

package trcs

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"sort"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
)

func newCombine(pather command.Pather) *cobra.Command {
	var flags struct {
		out     string
		payload string
		format  string
	}

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combine partially signed TRCs",
		Long: `'combine' combines the signatures on partially signed TRCs into one single TRC.
The command checks that all parts sign the same TRC payload contents, which is
provided with the '--payload' flag.

No further checks are made. Check that the TRC is valid and verifiable with the
appropriate commands.
`,
		Example: fmt.Sprintf(`  %[1]s combine --payload ISD1-B1-S1.pld -o ISD1-B1-S1.trc `+
			`ISD1-B1-S1.org1 ISD1-B1-S1.org2`, pather.CommandPath()),
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return RunCombine(args, flags.payload, flags.out, flags.format)
		},
	}

	addOutputFlag(&flags.out, cmd)
	cmd.Flags().StringVarP(&flags.payload, "payload", "p", "",
		"The ASN.1 DER encoded payload (required)")
	cmd.MarkFlagRequired("payload")
	cmd.Flags().StringVar(&flags.format, "format", "der", "Output format (der|pem)")

	return cmd
}

// RunCombine combines the partially signed TRC files and writes them to
// the out directory, pld is the payload file.
func RunCombine(files []string, pld, out string, format string) error {
	rawPld, err := ioutil.ReadFile(pld)
	if err != nil {
		return serrors.WrapStr("error loading payload", err)
	}
	block, _ := pem.Decode(rawPld)
	if block != nil && block.Type == "TRC PAYLOAD" {
		rawPld = block.Bytes
	}
	trcs := make(map[string]cppki.SignedTRC)
	for _, name := range files {
		dec, err := DecodeFromFile(name)
		if err != nil {
			return serrors.WrapStr("error decoding part", err, "file", name)
		}
		trcs[name] = dec
	}
	// Check all payloads are the same.
	var errs serrors.List
	for name, signed := range trcs {
		if !bytes.Equal(signed.TRC.Raw, rawPld) {
			errs = append(errs, serrors.New("different payload contents", "file", name))
		}
	}
	if err := errs.ToError(); err != nil {
		return err
	}
	infos, err := combineSignerInfos(trcs)
	if err != nil {
		return err
	}
	eci, err := protocol.NewDataEncapsulatedContentInfo(rawPld)
	if err != nil {
		return serrors.WrapStr("error encoding payload", err)
	}
	sd := protocol.SignedData{
		Version:          1,
		EncapContentInfo: eci,
		SignerInfos:      infos,
		DigestAlgorithms: combineDigestAlgorithms(infos),
	}
	// Write signed TRC.
	packed, err := sd.ContentInfoDER()
	if err != nil {
		return serrors.WrapStr("error packing combined TRC", err)
	}
	if format == "pem" {
		packed = pem.EncodeToMemory(&pem.Block{
			Type:  "TRC",
			Bytes: packed,
		})
	}
	if err := ioutil.WriteFile(out, packed, 0644); err != nil {
		return serrors.WrapStr("error writing combined TRC", err)
	}
	fmt.Printf("Successfully combined TRC at %s\n", out)
	return nil
}

// combineSignerInfos combines all singer infos. It checks that non-unique
// signer infos are equal. The returned slice is sorted.
func combineSignerInfos(trcs map[string]cppki.SignedTRC) ([]protocol.SignerInfo, error) {
	type SignerOrigin struct {
		Info protocol.SignerInfo
		File string
	}
	var errs serrors.List
	infos := make(map[string]SignerOrigin)
	for name, signed := range trcs {
		for _, si := range signed.SignerInfos {
			sid := string(si.SID.FullBytes)
			existing, ok := infos[sid]
			if !ok {
				infos[sid] = SignerOrigin{
					Info: si,
					File: name,
				}
				continue
			}
			if !cmp.Equal(si, existing.Info) {
				errs = append(errs, serrors.New("different SignerInfo contents for same subject",
					"files", []string{name, existing.File}))
			}
		}
	}
	if err := errs.ToError(); err != nil {
		return nil, err
	}
	var l []protocol.SignerInfo
	for _, info := range infos {
		l = append(l, info.Info)
	}
	// Keep sorting for consistent output for older go versions.
	// Starting from go1.15, the SignerInfos will be sorted when serializing.
	sort.Slice(l, func(i, j int) bool {
		return bytes.Compare(l[i].SID.FullBytes, l[j].SID.FullBytes) < 0
	})
	return l, nil
}

func combineDigestAlgorithms(infos []protocol.SignerInfo) []pkix.AlgorithmIdentifier {
	var algos []pkix.AlgorithmIdentifier
	for _, si := range infos {
		if !findDigestAlgorithm(si.DigestAlgorithm, algos) {
			algos = append(algos, si.DigestAlgorithm)
		}
	}
	sort.Slice(algos, func(i, j int) bool {
		return algos[i].Algorithm.String() < algos[j].Algorithm.String()
	})
	return algos
}

func findDigestAlgorithm(algo pkix.AlgorithmIdentifier, algos []pkix.AlgorithmIdentifier) bool {
	for _, existing := range algos {
		if existing.Algorithm.Equal(algo.Algorithm) {
			return bytes.Equal(existing.Parameters.FullBytes, algo.Parameters.FullBytes)
		}
	}
	return false
}
