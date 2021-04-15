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

package testcrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/scion-pki/trcs"
)

func newUpdate() *cobra.Command {
	var flags struct {
		out      string
		scenario string
	}

	cmd := &cobra.Command{
		Use:   "update",
		Args:  cobra.NoArgs,
		Short: "Generate TRC update for test topology",
		Long: `'update' generates a TRC update for a given scenario.

The TRC update is generated from the existing crypto material. The additional
material is put into the 'trcs' and 'certs' directory. The command searches for
the latest TRC available in the 'trcs' directory for each ISD and applies the
selected scenario.

Scenarios:

  - extend:
    regular update, certification path not broken

    In this scenario, the lifetime of all regular voting and root certificates
    is extended. I.e., new certificates authenticating the same private key are
    created and part of the updated TRC. The sensitive voting certificates are
    untouched.

  - re-sign:
    regular update, certification path not broken

    In this scenario, the certificates that are part of the updated TRC remain
    the same. Only the TRC lifetime is extended a bit.

  - re-gen:
	sensitive update, certificateion path broken

	In this scenario, all the voting and root certificates are changed for
	new ones.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(flags.out); err != nil {
				return err
			}
			cmd.SilenceUsage = true

			files, err := filepath.Glob(fmt.Sprintf("%s/trcs/ISD*.trc", flags.out))
			if err != nil {
				return err
			}

			isds := make(map[addr.ISD]cppki.SignedTRC)
			for _, file := range files {
				trc, err := trcs.DecodeFromFile(file)
				if err != nil {
					return serrors.WrapStr("loading TRC", err, "file", file)
				}
				if trc.TRC.ID.Serial > isds[trc.TRC.ID.ISD].TRC.ID.Serial {
					isds[trc.TRC.ID.ISD] = trc
				}
			}

			matches, err := filepath.Glob(filepath.Join(flags.out, "ISD*", "AS*"))
			out := outConfig{
				base: flags.out,
				isd:  err == nil && len(matches) != 0,
			}
			now := time.Now()
			for isd, predecessor := range isds {
				switch flags.scenario {
				case "extend":
					if err := extendTRC(now, out, predecessor); err != nil {
						return serrors.WrapStr("generating extension", err, "isd", isd)
					}
				case "re-sign":
					if err := resignTRC(now, out, predecessor); err != nil {
						return serrors.WrapStr("re-signing", err)
					}
				case "re-gen":
					if err := regenTRC(now, out, predecessor); err != nil {
						return err
					}
				default:
					return serrors.New("unknown scenario", "scenario", flags.scenario)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&flags.out, "out", "o", "gen", "Output directory")
	cmd.Flags().StringVar(&flags.scenario, "scenario", "extend", "TRC update scenario "+
		"(extend|re-sign|re-gen)")
	return cmd
}

func extendTRC(now time.Time, out outConfig, predecessor cppki.SignedTRC) error {
	id := cppki.TRCID{
		ISD:    predecessor.TRC.ID.ISD,
		Base:   predecessor.TRC.ID.Base,
		Serial: predecessor.TRC.ID.Serial + 1,
	}

	signers := map[*x509.Certificate]crypto.Signer{}
	var include []*x509.Certificate
	var votes []int
	for i, cert := range predecessor.TRC.Certificates {
		t, err := cppki.ValidateCert(cert)
		if err != nil {
			return err
		}
		ia, err := cppki.ExtractIA(cert.Subject)
		if err != nil {
			return err
		}
		switch t {
		case cppki.Regular:
			key, err := findkey(cryptoVotingDir(ia, out), cert)
			if err != nil {
				return serrors.WrapStr("searching key", err, "isd_as", ia, "type", t)
			}
			extended, err := extendCert(now, cert, key)
			if err != nil {
				return serrors.WrapStr("creating certificate", err, "isd_as", ia, "type", t)
			}
			file := filepath.Join(out.base, "certs", regularCertName(ia, int(id.Serial)))
			if err := writeCert(file, extended); err != nil {
				return serrors.WrapStr("writing certificate", err, "isd_as", ia, "type", t)
			}
			// Cast vote and show proof of possession.
			signers[cert] = key
			votes = append(votes, i)
			signers[extended] = key
			include = append(include, extended)
		case cppki.Root:
			key, err := findkey(cryptoCADir(ia, out), cert)
			if err != nil {
				return serrors.WrapStr("searching key", err, "isd_as", ia, "type", t)
			}
			extended, err := extendCert(now, cert, key)
			if err != nil {
				return serrors.WrapStr("creating certificate", err, "isd_as", ia, "type", t)
			}
			file := filepath.Join(out.base, "certs", rootCertName(ia, int(id.Serial)))
			if err := writeCert(file, extended); err != nil {
				return serrors.WrapStr("writing certificate", err, "isd_as", ia, "type", t)
			}
			// Show acknowledgment
			signers[cert] = key
			include = append(include, extended)
		case cppki.Sensitive:
			include = append(include, cert)
		}
	}

	pld := cppki.TRC{
		Version: 1,
		ID:      id,
		Validity: cppki.Validity{
			NotBefore: now,
			NotAfter:  now.Add(450 * 24 * time.Hour),
		},
		GracePeriod:       7 * 24 * time.Hour,
		Votes:             votes,
		Quorum:            predecessor.TRC.Quorum,
		CoreASes:          predecessor.TRC.CoreASes,
		AuthoritativeASes: predecessor.TRC.AuthoritativeASes,
		Description:       predecessor.TRC.Description,
		Certificates:      include,
	}
	trc, err := signTRC(pld, signers)
	if err != nil {
		return serrors.WrapStr("signing TRC", err)
	}
	return writeTRC(out, trc)
}

func resignTRC(now time.Time, out outConfig, predecessor cppki.SignedTRC) error {
	signers := map[*x509.Certificate]crypto.Signer{}
	var include []*x509.Certificate
	var votes []int
	for i, cert := range predecessor.TRC.Certificates {
		t, err := cppki.ValidateCert(cert)
		if err != nil {
			return err
		}
		ia, err := cppki.ExtractIA(cert.Subject)
		if err != nil {
			return err
		}
		if t == cppki.Regular {
			key, err := findkey(cryptoVotingDir(ia, out), cert)
			if err != nil {
				return serrors.WrapStr("searching key", err, "isd_as", ia, "type", t)
			}
			signers[cert] = key
			votes = append(votes, i)
		}
		include = append(include, cert)
	}

	pld := cppki.TRC{
		Version: 1,
		ID: cppki.TRCID{
			ISD:    predecessor.TRC.ID.ISD,
			Base:   predecessor.TRC.ID.Base,
			Serial: predecessor.TRC.ID.Serial + 1,
		},
		Validity: cppki.Validity{
			NotBefore: now,
			NotAfter:  now.Add(450 * 24 * time.Hour),
		},
		GracePeriod:       7 * 24 * time.Hour,
		Votes:             votes,
		Quorum:            predecessor.TRC.Quorum,
		CoreASes:          predecessor.TRC.CoreASes,
		AuthoritativeASes: predecessor.TRC.AuthoritativeASes,
		Description:       predecessor.TRC.Description,
		Certificates:      include,
	}
	trc, err := signTRC(pld, signers)
	if err != nil {
		return serrors.WrapStr("signing TRC", err)
	}
	return writeTRC(out, trc)
}

func regenTRC(now time.Time, out outConfig, predecessor cppki.SignedTRC) error {
	id := cppki.TRCID{
		ISD:    predecessor.TRC.ID.ISD,
		Base:   predecessor.TRC.ID.Base,
		Serial: predecessor.TRC.ID.Serial + 1,
	}

	signers := map[*x509.Certificate]crypto.Signer{}
	var include []*x509.Certificate
	var votes []int
	for i, cert := range predecessor.TRC.Certificates {
		ia, err := cppki.ExtractIA(cert.Subject)
		if err != nil {
			return err
		}
		t, err := cppki.ValidateCert(cert)
		if err != nil {
			return err
		}
		switch t {
		case cppki.Sensitive:
			dir := cryptoVotingDir(ia, out)
			key, err := findkey(dir, cert)
			if err != nil {
				return serrors.WrapStr("searching key", err, "isd_as", ia, "type", t)
			}
			newKey, err := createKey(fmt.Sprintf("%s/sensitive-voting.s%d.key", dir, id.Serial))
			if err != nil {
				return err
			}
			newCert, err := extendCert(now, cert, newKey)
			if err != nil {
				return serrors.WrapStr("creating certificate", err, "isd_as", ia, "type", t)
			}
			file := filepath.Join(out.base, "certs", sensitiveCertName(ia, int(id.Serial)))
			if err := writeCert(file, newCert); err != nil {
				return serrors.WrapStr("writing certificate", err, "isd_as", ia, "type", t)
			}
			// Cast vote and show proof of possession.
			signers[cert] = key
			votes = append(votes, i)
			signers[newCert] = newKey
			include = append(include, newCert)
		case cppki.Regular:
			dir := cryptoVotingDir(ia, out)
			newKey, err := createKey(fmt.Sprintf("%s/regular-voting.s%d.key", dir, id.Serial))
			if err != nil {
				return err
			}
			newCert, err := extendCert(now, cert, newKey)
			if err != nil {
				return serrors.WrapStr("creating certificate", err, "isd_as", ia, "type", t)
			}
			file := filepath.Join(out.base, "certs", regularCertName(ia, int(id.Serial)))
			if err := writeCert(file, newCert); err != nil {
				return serrors.WrapStr("writing certificate", err, "isd_as", ia, "type", t)
			}
			// Show proof of possession.
			signers[newCert] = newKey
			include = append(include, newCert)
		case cppki.Root:
			dir := cryptoCADir(ia, out)
			newKey, err := createKey(fmt.Sprintf("%s/cp-root.s%d.key", dir, id.Serial))
			if err != nil {
				return err
			}
			newCert, err := extendCert(now, cert, newKey)
			if err != nil {
				return serrors.WrapStr("creating certificate", err, "isd_as", ia, "type", t)
			}
			file := filepath.Join(out.base, "certs", rootCertName(ia, int(id.Serial)))
			if err := writeCert(file, newCert); err != nil {
				return serrors.WrapStr("writing certificate", err, "isd_as", ia, "type", t)
			}
			include = append(include, newCert)
		}
	}

	pld := cppki.TRC{
		Version: 1,
		ID:      id,
		Validity: cppki.Validity{
			NotBefore: now,
			NotAfter:  now.Add(450 * 24 * time.Hour),
		},
		GracePeriod:       7 * 24 * time.Hour,
		Votes:             votes,
		Quorum:            predecessor.TRC.Quorum,
		CoreASes:          predecessor.TRC.CoreASes,
		AuthoritativeASes: predecessor.TRC.AuthoritativeASes,
		Description:       predecessor.TRC.Description,
		Certificates:      include,
	}
	trc, err := signTRC(pld, signers)
	if err != nil {
		return serrors.WrapStr("signing TRC", err)
	}
	return writeTRC(out, trc)
}

func signTRC(pld cppki.TRC, signers map[*x509.Certificate]crypto.Signer) (cppki.SignedTRC, error) {
	raw, err := pld.Encode()
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	eci, err := protocol.NewDataEncapsulatedContentInfo(raw)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	sd, err := protocol.NewSignedData(eci)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	for cert, key := range signers {
		if err := sd.AddSignerInfo([]*x509.Certificate{cert}, key); err != nil {
			return cppki.SignedTRC{}, serrors.WithCtx(err, "common_name", cert.Subject.CommonName)
		}

	}
	return cppki.SignedTRC{
		TRC:         pld,
		SignerInfos: sd.SignerInfos,
	}, nil

}

func findkey(dir string, cert *x509.Certificate) (crypto.Signer, error) {
	files, err := filepath.Glob(dir + "/*.key")
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		raw, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "PRIVATE KEY" {
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		skid, err := cppki.SubjectKeyID(key.(crypto.Signer).Public())
		if err != nil {
			continue
		}
		if bytes.Equal(skid, cert.SubjectKeyId) {
			return key.(crypto.Signer), nil
		}
	}
	return nil, serrors.New("not found")
}

func createKey(file string) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	packed, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: packed,
	}
	raw := pem.EncodeToMemory(block)
	if raw == nil {
		return nil, serrors.New("failed to pack private key")
	}
	if err := ioutil.WriteFile(file, raw, 0644); err != nil {
		return nil, serrors.WrapStr("writing private key", err)
	}
	return key, nil
}

func extendCert(now time.Time, cert *x509.Certificate,
	key crypto.Signer) (*x509.Certificate, error) {

	// Choose random serial number.
	serial := make([]byte, 20)
	if _, err := rand.Read(serial); err != nil {
		return nil, serrors.WrapStr("creating random serial number", err)
	}
	// ExtraNames are used for marshaling
	subject := cert.Subject
	subject.ExtraNames = subject.Names

	tmpl := *cert
	tmpl.SignatureAlgorithm = cert.SignatureAlgorithm
	tmpl.NotBefore = now
	tmpl.NotAfter = now.Add(730 * 24 * time.Hour)
	tmpl.Subject = subject
	tmpl.SerialNumber = new(big.Int).SetBytes(serial)

	raw, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(raw)
}

func writeCert(file string, cert *x509.Certificate) error {
	out, err := os.Create(file)
	if err != nil {
		return err
	}
	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return err
	}
	return out.Close()
}

func writeTRC(out outConfig, trc cppki.SignedTRC) error {
	raw, err := trc.Encode()
	if err != nil {
		return serrors.WrapStr("encoding TRC", err)
	}
	file := filepath.Join(out.base, "trcs",
		fmt.Sprintf("ISD%d-B%d-S%d.trc", trc.TRC.ID.ISD, trc.TRC.ID.Base, trc.TRC.ID.Serial))
	return ioutil.WriteFile(file, raw, 0644)
}
