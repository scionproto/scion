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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
)

var (
	purposeVote     = "vote"
	purposeNewVoter = "new voter"
	purposeRootAck  = "root acknowledgement"
)

func newHuman(pather command.Pather) *cobra.Command {
	var flags struct {
		format      string
		strict      bool
		predecessor string
	}

	cmd := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"human"},
		Short:   "Represent TRC in a human readable form",
		Example: fmt.Sprintf(`  %[1]s human ISD1-B1-S1.pld.der
  %[1]s human ISD1-B1-S1.trc`, pather.CommandPath()),
		Long: `'human' outputs the TRC contents in a human readable form.

The input file can either be a TRC payload, or a signed TRC.
The output can either be in yaml, or json.

By default, this command attempts to handle decoding errors gracefully. To
return an error if parts of a TRC fail to decode, enable the strict mode.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			encoder, err := getEncoder(os.Stdout, flags.format)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true

			raw, err := ioutil.ReadFile(args[0])
			if err != nil {
				return err
			}
			var predTRC *cppki.TRC
			if flags.predecessor != "" {
				predRaw, err := ioutil.ReadFile(flags.predecessor)
				if err != nil {
					return err
				}
				predTRC, _, err = decodeTRCorPayload(predRaw)
				if err != nil {
					return err
				}
			}
			h, err := getHumanEncoding(raw, predTRC, flags.strict)
			if err != nil {
				return err
			}
			return encoder.Encode(h)
		},
	}
	cmd.Flags().StringVar(&flags.format, "format", "yaml", "Output format (yaml|json)")
	cmd.Flags().BoolVar(&flags.strict, "strict", false, "Enable strict decoding mode")
	cmd.Flags().StringVar(&flags.predecessor, "predecessor", "",
		"Predecessor TRC (needed to display signature purpose)")
	return cmd
}

func getEncoder(w io.Writer, format string) (interface{ Encode(v interface{}) error }, error) {
	switch format {
	case "yaml", "yml":
		return yaml.NewEncoder(w), nil
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "    ")
		return enc, nil
	default:
		return nil, serrors.New("format not supported", "format", format)
	}
}

func getHumanEncoding(raw []byte, predTRC *cppki.TRC, strict bool) (humanTRC, error) {
	var h humanTRC
	trc, signed, err := decodeTRCorPayload(raw)
	if err != nil {
		return humanTRC{}, serrors.New("file is neither TRC nor signed TRC")
	}
	if signed != nil {
		var predCerts []*x509.Certificate
		if predTRC != nil {
			predCerts = predTRC.Certificates
		}
		for i, info := range signed.SignerInfos {
			d, err := newSignerInfo(info, predCerts)
			if err != nil && strict {
				return humanTRC{}, serrors.WrapStr("decoding signer info", err, "index", i)
			}
			h.Signatures = append(h.Signatures, d)
		}
	}
	if err := h.setTRC(*trc); err != nil && strict {
		return humanTRC{}, err
	}
	return h, nil
}

func decodeTRCorPayload(raw []byte) (*cppki.TRC, *cppki.SignedTRC, error) {
	block, _ := pem.Decode(raw)
	if block != nil && (block.Type == "TRC" || block.Type == "TRC PAYLOAD") {
		raw = block.Bytes
	}
	if t, err := cppki.DecodeTRC(raw); err == nil {
		return &t, nil, nil
	} else if s, err := cppki.DecodeSignedTRC(raw); err == nil {
		return &s.TRC, &s, nil
	}
	return nil, nil, serrors.New("file is neither TRC nor signed TRC")
}

type humanTRC struct {
	Version int `yaml:"version" json:"version"`
	ID      struct {
		ISD    addr.ISD `yaml:"isd" json:"isd"`
		Base   uint64   `yaml:"base_number" json:"base_number"`
		Serial uint64   `yaml:"serial_number" json:"serial_number"`
	} `yaml:"id" json:"id"`
	Validity struct {
		NotBefore time.Time `yaml:"not_before" json:"not_before"`
		NotAfter  time.Time `yaml:"not_after" json:"not_after"`
	} `yaml:"validity" json:"validity"`
	GracePeriod       string       `yaml:"graceperiod,omitempty" json:"graceperiod,omitempty"`
	GracePeriodEnd    time.Time    `yaml:"graceperiod_end,omitempty" json:"graceperiod_end,omitempty"`
	NoTrustReset      bool         `yaml:"no_trust_reset" json:"no_trust_reset"`
	Votes             []int        `yaml:"votes,omitempty" json:"votes,omitempty"`
	Quorum            int          `yaml:"voting_quorum" json:"voting_quorum"`
	CoreASes          []addr.AS    `yaml:"core_ases" json:"core_ases"`
	AuthoritativeASes []addr.AS    `yaml:"authoritative_ases" json:"authoritative_ases"`
	Description       string       `yaml:"description" json:"description"`
	Certificates      []certDesc   `yaml:"certificates" json:"certificates"`
	Signatures        []signerInfo `yaml:"signatures,omitempty" json:"signatures,omitempty"`
}

func (h *humanTRC) setTRC(trc cppki.TRC) error {
	h.Version = trc.Version
	h.ID.ISD = trc.ID.ISD
	h.ID.Base = uint64(trc.ID.Base)
	h.ID.Serial = uint64(trc.ID.Serial)
	h.Validity.NotBefore = trc.Validity.NotBefore
	h.Validity.NotAfter = trc.Validity.NotAfter
	h.NoTrustReset = trc.NoTrustReset
	h.Votes = trc.Votes
	h.Quorum = trc.Quorum
	h.CoreASes = trc.CoreASes
	h.AuthoritativeASes = trc.AuthoritativeASes
	h.Description = trc.Description
	if !trc.ID.IsBase() {
		h.GracePeriod = trc.GracePeriod.String()
		h.GracePeriodEnd = trc.Validity.NotBefore.Add(trc.GracePeriod).UTC()
	}
	var errs serrors.List
	for i, cert := range trc.Certificates {
		if t, err := cppki.ValidateCert(cert); err != nil {
			h.Certificates = append(h.Certificates, certDesc{Error: err.Error()})
			errs = append(errs, serrors.WrapStr("classifying certificate", err, "index", i))
		} else {
			desc := certDesc{
				CommonName:   cert.Subject.CommonName,
				IA:           extractIA(cert.Subject),
				SerialNumber: fmt.Sprintf("% X", cert.SerialNumber.Bytes()),
				Type:         t.String(),
				Index:        i,
			}
			desc.Validity.NotBefore, desc.Validity.NotAfter = cert.NotBefore, cert.NotAfter
			h.Certificates = append(h.Certificates, desc)
		}
	}
	return errs.ToError()
}

type certDesc struct {
	Type         string  `yaml:"type,omitempty" json:"type,omitempty"`
	CommonName   string  `yaml:"common_name,omitempty" json:"common_name,omitempty"`
	IA           addr.IA `yaml:"isd_as,omitempty" json:"isd_as,omitempty"`
	SerialNumber string  `yaml:"serial_number,omitempty" json:"serial_number,omitempty"`
	Validity     struct {
		NotBefore time.Time `yaml:"not_before,omitempty" json:"not_before,omitempty"`
		NotAfter  time.Time `yaml:"not_after,omitempty" json:"not_after,omitempty"`
	} `yaml:"validity,omitempty" json:"validity,omitempty"`
	Index int    `yaml:"index" json:"index"`
	Error string `yaml:"error,omitempty" json:"error,omitempty"`
}

type signerInfo struct {
	CommonName   string    `yaml:"common_name,omitempty" json:"common_name,omitempty"`
	IA           addr.IA   `yaml:"isd_as,omitempty" json:"isd_as,omitempty"`
	SerialNumber string    `yaml:"serial_number,omitempty" json:"serial_number,omitempty"`
	SigningTime  time.Time `yaml:"signing_time,omitempty" json:"signing_time,omitempty"`
	Purpose      string    `yaml:"purpose,omitempty" json:"purpose,omitempty"`
	Error        string    `yaml:"error,omitempty" json:"error,omitempty"`
}

func newSignerInfo(info protocol.SignerInfo, certs []*x509.Certificate) (signerInfo, error) {
	if info.SID.Class != asn1.ClassUniversal || info.SID.Tag != asn1.TagSequence {
		err := serrors.New("unsupported signer info type")
		return signerInfo{Error: err.Error()}, err
	}
	var isn protocol.IssuerAndSerialNumber
	if rest, err := asn1.Unmarshal(info.SID.FullBytes, &isn); err != nil {
		return signerInfo{Error: err.Error()}, err
	} else if len(rest) > 0 {
		err := serrors.New("trailing data")
		return signerInfo{Error: err.Error()}, err
	}
	var issuer pkix.RDNSequence
	if rest, err := asn1.Unmarshal(isn.Issuer.FullBytes, &issuer); err != nil {
		return signerInfo{Error: err.Error()}, err
	} else if len(rest) != 0 {
		err := serrors.New("trailing data")
		return signerInfo{Error: err.Error()}, err
	}
	signingTime, err := info.GetSigningTimeAttribute()
	if err != nil {
		return signerInfo{Error: err.Error()}, err
	}

	var name pkix.Name
	name.FillFromRDNSequence(&issuer)
	return signerInfo{
		CommonName:   name.CommonName,
		IA:           extractIA(name),
		SerialNumber: fmt.Sprintf("% X", isn.SerialNumber.Bytes()),
		SigningTime:  signingTime,
		Purpose:      getPurpose(info, certs),
	}, nil
}

func extractIA(name pkix.Name) addr.IA {
	ia, err := cppki.ExtractIA(name)
	if err != nil {
		return addr.IA{}
	}
	return ia
}

func getPurpose(info protocol.SignerInfo, certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return ""
	}
	cert, err := info.FindCertificate(certs)
	if err == protocol.ErrNoCertificate {
		return purposeNewVoter
	} else if err != nil {
		return ""
	}
	certType, err := cppki.ValidateCert(cert)
	if err != nil {
		return ""
	}
	switch certType {
	case cppki.Sensitive, cppki.Regular:
		return purposeVote
	case cppki.Root:
		return purposeRootAck
	}
	return ""
}
