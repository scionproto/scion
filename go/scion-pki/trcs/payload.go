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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"sort"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/conf"
)

func newPayload(pather command.Pather) *cobra.Command {
	var flags struct {
		out    string
		tmpl   string
		pred   string
		format string
	}

	cmd := &cobra.Command{
		Use:   "payload",
		Short: "Generate new TRC payload",
		Example: fmt.Sprintf(`  %[1]s payload -t template.toml -o payload.der
  %[1]s payload -t template.toml -o payload.der -p predecessor.trc
		`,
			pather.CommandPath()),
		Long: `'payload' creates the asn.1 encoded der file.

To update an existing TRC the predecessor TRC needs to be specified.

To inspect the created asn.1 file you can use the openssl tool:
openssl asn1parse -inform DER -i -in payload.der
(for more information see 'man asn1parse')
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			cfg, err := conf.LoadTRC(flags.tmpl)
			if err != nil {
				return serrors.WrapStr("failed to load template file", err)
			}

			pred, err := loadPredecessor(cfg.SerialVersion == cfg.BaseVersion, flags.pred)
			if err != nil {
				return err
			}
			prepareCfg(&cfg, pred)
			trc, err := CreatePayload(cfg)
			if err != nil {
				return serrors.WrapStr("failed to marshal TRC", err)
			}
			if pred != nil {
				update, err := trc.ValidateUpdate(pred)
				if err != nil {
					return serrors.WrapStr("validating update", err)
				}
				printUpdate(update)
			}
			raw, err := trc.Encode()
			if err != nil {
				return serrors.WrapStr("encoding payload", err)
			}
			if flags.format == "pem" {
				raw = pem.EncodeToMemory(&pem.Block{
					Type:  "TRC PAYLOAD",
					Bytes: raw,
				})
			}
			err = ioutil.WriteFile(flags.out, raw, 0644)
			if err != nil {
				return serrors.WrapStr("failed to write file", err, "file", flags.out)
			}
			fmt.Printf("Successfully created payload at %s\n", flags.out)
			return nil
		},
	}

	addOutputFlag(&flags.out, cmd)
	cmd.Flags().StringVarP(&flags.tmpl, "template", "t", "", "Template file (required)")
	cmd.MarkFlagRequired("template")
	cmd.Flags().StringVarP(&flags.pred, "predecessor", "p", "", "Predecessor TRC")
	cmd.Flags().StringVar(&flags.format, "format", "der", "Output format (der|pem)")
	return cmd
}

func loadPredecessor(base bool, pred string) (*cppki.TRC, error) {
	if base && pred != "" {
		return nil, serrors.New("predecessor specified for base TRC")
	}
	if base {
		fmt.Println("Generating payload for base TRC.")
		return nil, nil
	}
	if pred == "" {
		return nil, serrors.New("missing predecessor file." +
			" Specify the predecessor TRC via --predecessor")
	}
	trc, err := DecodeFromFile(pred)
	if err != nil {
		return nil, serrors.WrapStr("loading predecessor TRC", err, "file", pred)
	}
	fmt.Println("Generating payload for TRC update.")
	return &trc.TRC, nil
}

func prepareCfg(cfg *conf.TRC, pred *cppki.TRC) {
	if pred == nil {
		sort.Slice(cfg.AuthoritativeASes, func(i, j int) bool {
			return cfg.AuthoritativeASes[i] < cfg.AuthoritativeASes[j]
		})
		sort.Slice(cfg.CoreASes, func(i, j int) bool {
			return cfg.CoreASes[i] < cfg.CoreASes[j]
		})
		return
	}
	// Keep this! TRCs generated with old version of the tool might not be
	// sorted.
	cfg.AuthoritativeASes = mimicOrder(cfg.AuthoritativeASes, pred.AuthoritativeASes)
	cfg.CoreASes = mimicOrder(cfg.CoreASes, pred.CoreASes)
	sort.Ints(cfg.Votes)
}

// mimicOrder mimics the order of the predecessor sequence. In a regular update,
// the sequence MUST not be changed, thus we attempt to mimic the order of the
// predecessor.
func mimicOrder(next, predecessor []addr.AS) []addr.AS {
	if len(next) != len(predecessor) {
		return next
	}
	m := map[addr.AS]struct{}{}
	for _, as := range predecessor {
		m[as] = struct{}{}
	}
	for _, as := range next {
		if _, ok := m[as]; !ok {
			return next
		}
	}
	return predecessor
}

func printUpdate(update cppki.Update) {
	type desc struct {
		Type   string `yaml:"type"`
		CN     string `yaml:"common name"`
		Serial string `yaml:"serial number"`
	}
	var descs []desc
	for _, v := range []struct {
		Type  string
		Certs []*x509.Certificate
	}{
		{Type: "vote", Certs: update.Votes},
		{Type: "proof of possession", Certs: update.NewVoters},
		{Type: "acknowledgement", Certs: update.RootAcknowledgments},
	} {
		sort.Slice(v.Certs, func(i, j int) bool {
			return v.Certs[i].Subject.CommonName < v.Certs[j].Subject.CommonName
		})
		for _, cert := range v.Certs {
			descs = append(descs, desc{
				Type:   v.Type,
				CN:     cert.Subject.CommonName,
				Serial: fmt.Sprintf("% X", cert.SerialNumber.Bytes()),
			})
		}

	}
	out, err := yaml.Marshal(map[string][]desc{"required signatures": descs})
	if err != nil {
		return
	}
	fmt.Printf("\n%s\n", string(out))
}
