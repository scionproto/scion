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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/certs"
	"github.com/scionproto/scion/scion-pki/conf"
	"github.com/scionproto/scion/scion-pki/key"
	"github.com/scionproto/scion/scion-pki/trcs"
)

func Cmd(pather command.Pather) *cobra.Command {
	var flags struct {
		topo       string
		out        string
		noCleanup  bool
		isdDir     bool
		asValidity string
	}

	cmd := &cobra.Command{
		Use:     "testcrypto",
		Short:   "Generate crypto material for test topology",
		Example: fmt.Sprintf(`  %[1]s testcrypto -t testing.topo -o gen`, pather.CommandPath()),
		Hidden:  true,
		Long: `'testcrypto' generates the crypto material for a test topology.

This command should only be used in testing.
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			asValidity, err := util.ParseDuration(flags.asValidity)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			return testcrypto(
				flags.topo,
				flags.out,
				flags.noCleanup,
				flags.isdDir,
				asValidity,
				cmd.OutOrStdout(),
			)
		},
	}

	cmd.Flags().StringVarP(&flags.topo, "topo", "t", "", "Topology description file (required)")
	cmd.Flags().StringVarP(&flags.out, "out", "o", "gen", "Output directory")
	cmd.Flags().BoolVar(&flags.isdDir, "isd-dir", false, "Group ASes in ISD directory")
	cmd.Flags().StringVar(&flags.asValidity, "as-validity", "3d", "AS certificate validity")
	cmd.MarkFlagRequired("topo")

	cmd.AddCommand(newUpdate())

	return cmd
}

type config struct {
	topo       topo
	out        outConfig
	now        time.Time
	asValidity time.Duration
	writer     io.Writer
}

func testcrypto(
	topo string,
	outDir string,
	noCleanup bool,
	isdDir bool,
	asValidity time.Duration,
	writer io.Writer,
) error {

	t, err := loadTopo(topo)
	if err != nil {
		return err
	}
	out := outConfig{
		base: outDir,
		isd:  isdDir,
	}
	if err := prepareDirectories(t, out); err != nil {
		return err
	}

	cfg := config{
		topo:       t,
		out:        out,
		now:        time.Now().Add(-time.Minute),
		asValidity: asValidity,
		writer:     writer,
	}

	if err := setupTemplates(cfg); err != nil {
		return err
	}
	if err := createVoters(cfg); err != nil {
		return err
	}
	if err := createCAs(cfg); err != nil {
		return err
	}
	if err := createASes(cfg); err != nil {
		return err
	}
	if err := createTRCs(cfg); err != nil {
		return err
	}
	if err := flatten(out); err != nil {
		return err
	}
	if !noCleanup {
		if err := cleanup(cfg); err != nil {
			return err
		}
	}
	return nil
}

func createVoters(cfg config) error {
	for ia, d := range cfg.topo.ASes {
		if !d.Voting {
			continue
		}
		fmt.Fprintf(cfg.writer, "Generate sensitive and regular voting certificate for %s\n", ia)
		votingDir := cryptoVotingDir(ia, cfg.out)

		cmd := certs.Cmd(command.StringPather("certificate"))
		cmd.SetArgs([]string{
			"create",
			filepath.Join(votingDir, "sensitive.tmpl"),
			filepath.Join(votingDir, sensitiveCertName(ia)),
			filepath.Join(votingDir, "sensitive-voting.key"),
			"--profile=sensitive-voting",
			"--not-before=" + strconv.Itoa(int(cfg.now.Unix())),
			"--not-after=730d",
		})
		if err := cmd.Execute(); err != nil {
			return err
		}
		err := copyFile(
			filepath.Join(votingDir, "sensitive-voting.crt"),
			filepath.Join(votingDir, sensitiveCertName(ia)),
		)
		if err != nil {
			return err
		}

		cmd = certs.Cmd(command.StringPather("certificate"))
		cmd.SetArgs([]string{
			"create",
			filepath.Join(votingDir, "regular.tmpl"),
			filepath.Join(votingDir, regularCertName(ia)),
			filepath.Join(votingDir, "regular-voting.key"),
			"--profile=regular-voting",
			"--not-before=" + strconv.Itoa(int(cfg.now.Unix())),
			"--not-after=730d",
		})
		if err := cmd.Execute(); err != nil {
			return err
		}
		err = copyFile(
			filepath.Join(votingDir, "regular-voting.crt"),
			filepath.Join(votingDir, regularCertName(ia)),
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func createCAs(cfg config) error {
	for ia, d := range cfg.topo.ASes {
		if !d.Issuing {
			continue
		}
		fmt.Fprintf(cfg.writer, "Generate CP Root and CP CA certificate for %s\n", ia)
		caDir := cryptoCADir(ia, cfg.out)

		cmd := certs.Cmd(command.StringPather("certificate"))
		cmd.SetArgs([]string{
			"create",
			filepath.Join(caDir, "cp-root.tmpl"),
			filepath.Join(caDir, rootCertName(ia)),
			filepath.Join(caDir, "cp-root.key"),
			"--profile=cp-root",
			"--not-before=" + strconv.Itoa(int(cfg.now.Unix())),
			"--not-after=730d",
		})
		if err := cmd.Execute(); err != nil {
			return err
		}

		cmd = certs.Cmd(command.StringPather("certificate"))
		cmd.SetArgs([]string{
			"create",
			filepath.Join(caDir, "cp-ca.tmpl"),
			filepath.Join(caDir, caCertName(ia)),
			filepath.Join(caDir, "cp-ca.key"),
			"--profile=cp-ca",
			"--not-before=" + strconv.Itoa(int(cfg.now.Unix())),
			"--not-after=700d",
			"--ca=" + filepath.Join(caDir, rootCertName(ia)),
			"--ca-key=" + filepath.Join(caDir, "cp-root.key"),
		})
		if err := cmd.Execute(); err != nil {
			return err
		}
	}
	return nil
}

func createASes(cfg config) error {
	for ia, d := range cfg.topo.ASes {
		ca := d.CA
		fmt.Fprintf(cfg.writer, "Generate CP AS certificate for %s issued by %s\n", ia, ca)
		caDir := cryptoCADir(ca, cfg.out)
		asDir := cryptoASDir(ia, cfg.out)

		cmd := certs.Cmd(command.StringPather("certificate"))
		cmd.SetArgs([]string{
			"create",
			filepath.Join(asDir, "cp-as.tmpl"),
			filepath.Join(asDir, chainName(ia)),
			filepath.Join(asDir, "cp-as.key"),
			"--profile=cp-as",
			"--not-before=" + strconv.Itoa(int(cfg.now.Unix())),
			"--not-after=" + util.FmtDuration(cfg.asValidity),
			"--ca=" + filepath.Join(caDir, caCertName(ca)),
			"--ca-key=" + filepath.Join(caDir, "cp-ca.key"),
			"--bundle",
		})
		if err := cmd.Execute(); err != nil {
			return err
		}
	}
	return nil
}

type voterInfo struct {
	sensitiveKey  crypto.Signer
	sensitiveCert *x509.Certificate
	regularKey    crypto.Signer
	regularCert   *x509.Certificate
}

func createTRCs(cfg config) error {
	authoritatives := make(map[addr.ISD][]addr.AS)
	cores := make(map[addr.ISD][]addr.AS)
	issuers := make(map[addr.ISD][]addr.IA)
	voters := make(map[addr.ISD][]addr.IA)
	certFiles := make(map[addr.ISD][]string)
	isds := make(map[addr.ISD]struct{})
	for ia, d := range cfg.topo.ASes {
		isds[ia.ISD()] = struct{}{}
		if d.Authoritative {
			authoritatives[ia.ISD()] = append(authoritatives[ia.ISD()], ia.AS())
		}
		if d.Core {
			cores[ia.ISD()] = append(cores[ia.ISD()], ia.AS())
		}
		if d.Issuing {
			issuers[ia.ISD()] = append(issuers[ia.ISD()], ia)
			certFiles[ia.ISD()] = append(certFiles[ia.ISD()],
				filepath.Join(cryptoCADir(ia, cfg.out), rootCertName(ia)))
		}
		if d.Voting {
			voters[ia.ISD()] = append(voters[ia.ISD()], ia)
			certFiles[ia.ISD()] = append(certFiles[ia.ISD()],
				filepath.Join(cryptoVotingDir(ia, cfg.out), regularCertName(ia)),
				filepath.Join(cryptoVotingDir(ia, cfg.out), sensitiveCertName(ia)),
			)
		}
	}
	for isd := range isds {
		trcConf := conf.TRC{
			ISD:           isd,
			Description:   fmt.Sprintf("Testcrypto TRC for ISD %d", isd),
			SerialVersion: 1,
			BaseVersion:   1,
			VotingQuorum:  uint8(len(voters[isd])/2 + 1),
			Validity: conf.Validity{
				NotBefore: conf.Time(cfg.now.UTC()),
				Validity:  util.DurWrap{Duration: 450 * 24 * time.Hour},
			},
			CoreASes:          cores[isd],
			AuthoritativeASes: authoritatives[isd],
			CertificateFiles:  certFiles[isd],
		}
		sort.Strings(trcConf.CertificateFiles)
		trc, err := trcs.CreatePayload(trcConf, nil)
		if err != nil {
			return serrors.Wrap("creating TRC payload", err, "isd", isd)
		}
		raw, err := trc.Encode()
		if err != nil {
			return serrors.Wrap("encoding TRC payload", err, "isd", isd)
		}

		parts := make(map[string]cppki.SignedTRC, len(voters[isd])*2)
		for _, voter := range voters[isd] {
			voterInfo, err := loadVoterInfo(voter, cryptoVotingDir(voter, cfg.out))
			if err != nil {
				return err
			}

			sensitive, err := signPayload(raw, voterInfo.sensitiveKey, voterInfo.sensitiveCert)
			if err != nil {
				return serrors.Wrap("signing TRC payload - sensitive", err)
			}
			parts[fmt.Sprintf("ISD%d-B1-S1.%s-sensitive.trc", isd, voter)] = sensitive
			regular, err := signPayload(raw, voterInfo.regularKey, voterInfo.regularCert)
			if err != nil {
				return serrors.Wrap("signing TRC payload - regular", err)
			}
			parts[fmt.Sprintf("ISD%d-B1-S1.%s-regular.trc", isd, voter)] = regular
		}

		combined, err := trcs.CombineSignedPayloads(parts)
		if err != nil {
			return serrors.Wrap("combining signed TRC payloads", err)
		}
		combined = pem.EncodeToMemory(&pem.Block{
			Type:  "TRC",
			Bytes: combined,
		})
		if err := os.WriteFile(filepath.Join(trcDir(isd, cfg.out),
			fmt.Sprintf("ISD%d-B1-S1.trc", isd)), combined, 0644); err != nil {
			return serrors.Wrap("writing TRC", err)
		}
	}
	return nil
}

func loadVoterInfo(voter addr.IA, votingDir string) (*voterInfo, error) {
	sensitiveKey, err := key.LoadPrivateKey("", filepath.Join(votingDir, "sensitive-voting.key"))
	if err != nil {
		return nil, serrors.Wrap("loading sensitive key", err)
	}
	regularKey, err := key.LoadPrivateKey("", filepath.Join(votingDir, "regular-voting.key"))
	if err != nil {
		return nil, serrors.Wrap("loading regular key", err)
	}
	sensitiveCerts, err := cppki.ReadPEMCerts(
		filepath.Join(votingDir, sensitiveCertName(voter)))
	if err != nil {
		return nil, serrors.Wrap("loading sensitive cert", err)
	}
	if len(sensitiveCerts) > 1 {
		return nil, serrors.New("more than one sensitive cert found", "ia", voter)
	}
	regularCerts, err := cppki.ReadPEMCerts(
		filepath.Join(votingDir, regularCertName(voter)))
	if err != nil {
		return nil, serrors.Wrap("loading regular cert", err)
	}
	if len(regularCerts) > 1 {
		return nil, serrors.New("more than one regular cert found", "ia", voter)
	}

	return &voterInfo{
		sensitiveKey:  sensitiveKey,
		regularKey:    regularKey,
		sensitiveCert: sensitiveCerts[0],
		regularCert:   regularCerts[0],
	}, nil
}

func signPayload(pld []byte, key crypto.Signer, cert *x509.Certificate) (cppki.SignedTRC, error) {
	signedPld, err := trcs.SignPayload(pld, key, cert)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	return cppki.DecodeSignedTRC(signedPld)
}

func setupTemplates(cfg config) error {
	for ia, d := range cfg.topo.ASes {
		files := map[string]certs.SubjectVars{
			filepath.Join(cryptoASDir(ia, cfg.out), "cp-as.tmpl"): {
				IA:         ia,
				CommonName: ia.String() + " AS Certificate",
			},
		}
		if d.Issuing {
			files[filepath.Join(cryptoCADir(ia, cfg.out), "cp-root.tmpl")] = certs.SubjectVars{
				IA:         ia,
				CommonName: ia.String() + " Root Certificate - GEN I",
			}
			files[filepath.Join(cryptoCADir(ia, cfg.out), "cp-ca.tmpl")] = certs.SubjectVars{
				IA:         ia,
				CommonName: fmt.Sprintf("%s CA Certificate - GEN I %d.1", ia, time.Now().Year()),
			}
		}
		if d.Voting {
			files[filepath.Join(cryptoVotingDir(ia, cfg.out), "regular.tmpl")] = certs.SubjectVars{
				IA:         ia,
				CommonName: ia.String() + " Regular Voting Certificate",
			}
			files[filepath.Join(cryptoVotingDir(ia, cfg.out), "sensitive.tmpl")] =
				certs.SubjectVars{
					IA:         ia,
					CommonName: ia.String() + " Sensitive Voting Certificate",
				}
		}
		for fn, tmpl := range files {
			file, err := os.Create(fn)
			if err != nil {
				return err
			}
			defer file.Close()
			enc := json.NewEncoder(file)
			enc.SetIndent("", "    ")
			if err := enc.Encode(tmpl); err != nil {
				return err
			}
		}
	}
	return nil
}

func prepareDirectories(t topo, out outConfig) error {
	for ia, d := range t.ASes {
		dirs := []string{
			trcDir(ia.ISD(), out),
			keyDir(ia, out),
			certDir(ia, out),
			cryptoASDir(ia, out),
			filepath.Join(out.base, "trcs"),
			filepath.Join(out.base, "certs"),
		}
		if d.Issuing {
			dirs = append(dirs, cryptoCADir(ia, out))
		}
		if d.Voting {
			dirs = append(dirs, cryptoVotingDir(ia, out))
		}
		for _, dir := range dirs {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return err
			}
		}
	}
	return nil
}

func flatten(out outConfig) error {
	trcs, err := filepath.Glob(fmt.Sprintf("%s/ISD*/trcs/ISD*-B*-S*.trc", out.base))
	if err != nil {
		return err
	}
	for _, trc := range trcs {
		_, name := filepath.Split(trc)
		if err := copyFile(filepath.Join(out.base, "trcs", name), trc); err != nil {
			return serrors.Wrap("copying", err, "file", trc)
		}
	}

	prefix := filepath.Join(out.base, "AS*")
	if out.isd {
		prefix = filepath.Join(out.base, "ISD*", "AS*")
	}

	pems, err := filepath.Glob(fmt.Sprintf("%s/crypto/*/ISD*-AS*.pem", prefix))
	if err != nil {
		return err
	}
	crts, err := filepath.Glob(fmt.Sprintf("%s/crypto/*/ISD*-AS*.crt", prefix))
	if err != nil {
		return err
	}
	for _, file := range append(pems, crts...) {
		_, name := filepath.Split(file)
		if err := copyFile(filepath.Join(out.base, "certs", name), file); err != nil {
			return serrors.Wrap("copying", err, "file", file)
		}
	}
	return nil
}

func cleanup(cfg config) error {
	base := cfg.out.base
	if cfg.out.isd {
		base = filepath.Join(base, "*/")
	}
	var files []string
	match, err := filepath.Glob(filepath.Join(base, "*/crypto/*/cp-*.crt"))
	if err != nil {
		return err
	}
	files = append(files, match...)
	match, err = filepath.Glob(filepath.Join(base, "*/crypto/*/regular-*.crt"))
	if err != nil {
		return err
	}
	files = append(files, match...)
	match, err = filepath.Glob(filepath.Join(base, "*/crypto/*/sensitive-*.crt"))
	if err != nil {
		return err
	}
	files = append(files, match...)
	match, err = filepath.Glob(filepath.Join(base, "*/crypto/voting/ISD*-B1-S1.*.trc"))
	if err != nil {
		return err
	}
	files = append(files, match...)
	for _, file := range files {
		if err := os.Remove(file); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(dst string, src string) error {
	if dst == src {
		return nil
	}
	dfile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dfile.Close()
	sfile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sfile.Close()
	if _, err := io.Copy(dfile, sfile); err != nil {
		return err
	}
	return nil
}

type outConfig struct {
	base string
	isd  bool
}

func (cfg outConfig) AS(ia addr.IA) string {
	if cfg.isd {
		return filepath.Join(
			cfg.base,
			addr.FormatISD(ia.ISD(), addr.WithDefaultPrefix()),
			addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator()),
		)
	}
	return filepath.Join(
		cfg.base,
		addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator()),
	)
}

func trcDir(isd addr.ISD, out outConfig) string {
	return filepath.Join(out.base, addr.FormatISD(isd, addr.WithDefaultPrefix()), "trcs")
}

func keyDir(ia addr.IA, out outConfig) string {
	return filepath.Join(out.AS(ia), "keys")
}

func certDir(ia addr.IA, out outConfig) string {
	return filepath.Join(out.AS(ia), "certs")
}

func cryptoASDir(ia addr.IA, out outConfig) string {
	return filepath.Join(out.AS(ia), "crypto", "as")
}

func cryptoCADir(ia addr.IA, out outConfig) string {
	return filepath.Join(out.AS(ia), "crypto", "ca")
}

func cryptoVotingDir(ia addr.IA, out outConfig) string {
	return filepath.Join(out.AS(ia), "crypto", "voting")
}

func chainName(ia addr.IA) string {
	return fmt.Sprintf("%s.pem", fmtIA(ia))
}

func caCertName(ia addr.IA) string {
	return fmt.Sprintf("%s.ca.crt", fmtIA(ia))
}

func rootCertName(ia addr.IA, serial ...int) string {
	if len(serial) == 0 {
		return fmt.Sprintf("%s.root.crt", fmtIA(ia))
	}
	return fmt.Sprintf("%s.root.s%d.crt", fmtIA(ia), serial[0])
}

func sensitiveCertName(ia addr.IA, serial ...int) string {
	if len(serial) == 0 {
		return fmt.Sprintf("%s.sensitive.crt", fmtIA(ia))
	}
	return fmt.Sprintf("%s.sensitive.s%d.crt", fmtIA(ia), serial[0])
}

func regularCertName(ia addr.IA, serial ...int) string {
	if len(serial) == 0 {
		return fmt.Sprintf("%s.regular.crt", fmtIA(ia))
	}
	return fmt.Sprintf("%s.regular.s%d.crt", fmtIA(ia), serial[0])
}

func fmtIA(ia addr.IA) string {
	return addr.FormatIA(ia, addr.WithFileSeparator(), addr.WithDefaultPrefix())
}
