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
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/conf"
	"github.com/scionproto/scion/go/scion-pki/trcs"
)

const defaultCryptoLib = "./scripts/cryptoplayground/crypto_lib.sh"

func Cmd(pather command.Pather) *cobra.Command {
	var flags struct {
		topo      string
		out       string
		cryptoLib string
		noCleanup bool
		isdDir    bool
	}

	// cmd implements the testcrypto sub-command. The bash library needs to be
	// present on the file system. This approach is brittle when distributing the
	// application. But this is only a temporary solution for generating the test
	// crypto material and should be enough.
	cmd := &cobra.Command{
		Use:     "testcrypto",
		Short:   "Generate crypto material for test topology",
		Example: fmt.Sprintf(`  %[1]s testcrypto -t testing.topo -o gen`, pather.CommandPath()),
		Hidden:  true,
		Long: `'testcrypto' generates the crypto material for a test topology.

To generate the crypto material, this command calls out to a docker container
running openssl. In order for it to succeed, the crypto_lib must be available.
This command should only be used in testing.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if flags.cryptoLib == defaultCryptoLib {
				if altLib, ok := os.LookupEnv("CRYPTOLIB"); ok {
					flags.cryptoLib = altLib
				}
			}
			cmd.SilenceUsage = true
			return testcrypto(flags.topo, flags.cryptoLib, flags.out, flags.noCleanup, flags.isdDir)
		},
	}

	cmd.Flags().StringVarP(&flags.topo, "topo", "t", "", "Topology description file (required)")
	cmd.Flags().StringVarP(&flags.out, "out", "o", "gen", "Output directory")
	cmd.Flags().StringVarP(&flags.cryptoLib, "cryptolib", "l",
		defaultCryptoLib, "Path to bash crypto library")
	cmd.Flags().BoolVar(&flags.noCleanup, "no-cleanup", false, "Do not clean up openssl artifacts")
	cmd.Flags().BoolVar(&flags.isdDir, "isd-dir", false, "Group ASes in ISD directory")
	cmd.MarkFlagRequired("topo")

	cmd.AddCommand(newUpdate())

	return cmd
}

type config struct {
	topo      topo
	out       outConfig
	container string
	lib       string
	now       time.Time
}

func testcrypto(topo, cryptoLib, outDir string, noCleanup, isdDir bool) error {
	t, err := loadTopo(topo)
	if err != nil {
		return err
	}
	lib, err := filepath.Abs(cryptoLib)
	if err != nil {
		return err
	}
	base, err := filepath.Abs(outDir)
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
	container, err := startDocker(base, lib)
	if err != nil {
		return err
	}
	defer stopDocker(container, lib)

	cfg := config{
		topo:      t,
		container: container,
		out:       out,
		lib:       lib,
		now:       time.Now(),
	}

	if err := setupOpenSSLConfigs(cfg); err != nil {
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
	if err := fixPermissions(cfg); err != nil {
		return err
	}
	if !noCleanup {
		if err := cleanup(cfg); err != nil {
			return err
		}
	}
	return nil
}

func startDocker(out, lib string) (string, error) {
	container := fmt.Sprintf("crypto_lib_%x", rand.Uint64())
	cmd := exec.Command("sh", "-c", withLib("start_docker", lib))
	cmd.Dir = out
	cmd.Env = []string{
		"PLAYGROUND=" + filepath.Dir(lib),
		"CONTAINER_NAME=" + container,
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return container, cmd.Run()
}

func stopDocker(container, lib string) {
	cmd := exec.Command("sh", "-c", withLib("stop_docker", lib))
	cmd.Env = []string{"CONTAINER_NAME=" + container}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Run()
}

func createVoters(cfg config) error {
	for ia, d := range cfg.topo.ASes {
		if !d.Voting {
			continue
		}
		fmt.Printf("Generate sensitive and regular voting certificate for %s\n", ia)

		cmd := exec.Command("sh", "-c", withLib("prepare_ca", cfg.lib))
		cmd.Dir = cryptoVotingDir(ia, cfg.out)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}

		cmd = exec.Command("sh", "-c", withLib("docker_exec "+
			`"navigate_pubdir && gen_sensitive && gen_regular"`, cfg.lib))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Env = []string{
			"STARTDATE=" + generalizedTime(cfg.now),
			"ENDDATE=" + generalizedTime(cfg.now.Add(730*24*time.Hour)),
			"KEYDIR=" + cryptoVotingDir(ia, outConfig{base: "/workdir", isd: cfg.out.isd}),
			"PUBDIR=" + cryptoVotingDir(ia, outConfig{base: "/workdir", isd: cfg.out.isd}),
			"CONTAINER_NAME=" + cfg.container,
		}
		if err := cmd.Run(); err != nil {
			return err
		}

		votingDir := cryptoVotingDir(ia, cfg.out)
		err := copyFile(filepath.Join(votingDir, sensitiveCertName(ia)),
			filepath.Join(votingDir, "sensitive-voting.crt"))
		if err != nil {
			return err
		}
		err = copyFile(filepath.Join(votingDir, regularCertName(ia)),
			filepath.Join(votingDir, "regular-voting.crt"))
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
		fmt.Printf("Generate CP Root and CP CA certificate for %s\n", ia)

		cmd := exec.Command("sh", "-c", withLib("prepare_ca", cfg.lib))
		cmd.Dir = cryptoCADir(ia, cfg.out)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}

		cmd = exec.Command("sh", "-c", withLib(`docker_exec "`+
			`navigate_pubdir && gen_root && gen_ca"`, cfg.lib))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Env = []string{
			"STARTDATE=" + generalizedTime(cfg.now),
			"ENDDATE=" + generalizedTime(cfg.now.Add(730*24*time.Hour)),
			"KEYDIR=" + cryptoCADir(ia, outConfig{base: "/workdir", isd: cfg.out.isd}),
			"PUBDIR=" + cryptoCADir(ia, outConfig{base: "/workdir", isd: cfg.out.isd}),
			"CONTAINER_NAME=" + cfg.container,
		}
		if err := cmd.Run(); err != nil {
			return err
		}

		caDir := cryptoCADir(ia, cfg.out)
		err := copyFile(filepath.Join(caDir, rootCertName(ia)), filepath.Join(caDir, "cp-root.crt"))
		if err != nil {
			return err
		}
		err = copyFile(filepath.Join(caDir, caCertName(ia)), filepath.Join(caDir, "cp-ca.crt"))
		if err != nil {
			return err
		}
	}
	return nil
}

func createASes(cfg config) error {
	for ia, d := range cfg.topo.ASes {
		ca := d.CA
		caDir := cryptoCADir(ca, cfg.out)

		fmt.Printf("Generate CP AS certificate for %s issued by %s\n", ia, ca)

		asDir := cryptoASDir(ia, cfg.out)

		cmd := exec.Command("sh", "-c", withLib(`docker_exec "`+
			`navigate_pubdir && `+
			`gen_as_as_steps && `+
			`chmod 0666 cp-as.csr"`, cfg.lib))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Env = []string{
			"STARTDATE=" + generalizedTime(cfg.now),
			"ENDDATE=" + generalizedTime(cfg.now.Add(365*24*time.Hour)),
			"KEYDIR=" + cryptoASDir(ia, outConfig{base: "/workdir", isd: cfg.out.isd}),
			"PUBDIR=" + cryptoASDir(ia, outConfig{base: "/workdir", isd: cfg.out.isd}),
			"CONTAINER_NAME=" + cfg.container,
		}
		if err := cmd.Run(); err != nil {
			return err
		}

		err := copyFile(filepath.Join(caDir, "cp-as.csr"), filepath.Join(asDir, "cp-as.csr"))
		if err != nil {
			return err
		}

		cmd = exec.Command("sh", "-c", withLib(`docker_exec "`+
			`navigate_pubdir && `+
			`gen_as_ca_steps && `+
			`cat cp-ca.crt >> cp-as.crt && `+
			`chmod 0666 cp-as.crt"`, cfg.lib))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Env = []string{
			"STARTDATE=" + generalizedTime(cfg.now),
			"ENDDATE=" + generalizedTime(cfg.now.Add(365*24*time.Hour)),
			"KEYDIR=" + cryptoCADir(ca, outConfig{base: "/workdir", isd: cfg.out.isd}),
			"PUBDIR=" + cryptoCADir(ca, outConfig{base: "/workdir", isd: cfg.out.isd}),
			"CONTAINER_NAME=" + cfg.container,
		}
		if err := cmd.Run(); err != nil {
			return err
		}
		err = copyFile(filepath.Join(asDir, chainName(ia)), filepath.Join(caDir, "cp-as.crt"))
		if err != nil {
			return err
		}
		err = copyFile(filepath.Join(cryptoCAClientDir(ca, cfg.out), chainName(ia)),
			filepath.Join(caDir, "cp-as.crt"))
		if err != nil {
			return err
		}
	}
	return nil
}

func createTRCs(cfg config) error {
	authoritatives := make(map[addr.ISD][]addr.AS)
	cores := make(map[addr.ISD][]addr.AS)
	issuers := make(map[addr.ISD][]addr.IA)
	voters := make(map[addr.ISD][]addr.IA)
	certFiles := make(map[addr.ISD][]string)
	isds := make(map[addr.ISD]struct{})
	for ia, d := range cfg.topo.ASes {
		isds[ia.I] = struct{}{}
		if d.Authoritative {
			authoritatives[ia.I] = append(authoritatives[ia.I], ia.A)
		}
		if d.Core {
			cores[ia.I] = append(cores[ia.I], ia.A)
		}
		if d.Issuing {
			issuers[ia.I] = append(issuers[ia.I], ia)
			certFiles[ia.I] = append(certFiles[ia.I],
				filepath.Join(cryptoCADir(ia, cfg.out), rootCertName(ia)))
		}
		if d.Voting {
			voters[ia.I] = append(voters[ia.I], ia)
			certFiles[ia.I] = append(certFiles[ia.I],
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
				NotBefore: uint32(cfg.now.UTC().Unix()),
				Validity:  util.DurWrap{Duration: 450 * 24 * time.Hour},
			},
			CoreASes:          cores[isd],
			AuthoritativeASes: authoritatives[isd],
			CertificateFiles:  certFiles[isd],
		}
		sort.Strings(trcConf.CertificateFiles)
		trc, err := trcs.CreatePayload(trcConf)
		if err != nil {
			return serrors.WrapStr("creating TRC", err, "isd", isd)
		}
		raw, err := trc.Encode()
		if err != nil {
			return serrors.WrapStr("encoding TRC", err, "isd", isd)
		}
		pldName := filepath.Join(cfg.out.base, fmt.Sprintf("ISD%d", isd), "TRC-B1-S1.pld.der")
		err = ioutil.WriteFile(pldName, raw, 0666)
		if err != nil {
			return serrors.WrapStr("failed to write TRC payload", err, "isd", isd)
		}
		partFiles := make([]string, 0, len(voters[isd])*2)
		for _, voter := range voters[isd] {
			cmd := exec.Command("sh", "-c", withLib(fmt.Sprintf(`docker_exec "
				cp /workdir/ISD%d/TRC-B1-S1.pld.der $PUBDIR/ISD-B1-S1.pld.der &&
				navigate_pubdir &&
				sign_payload"`, isd), cfg.lib))
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			cmd.Env = []string{
				"KEYDIR=" + cryptoVotingDir(voter, outConfig{base: "/workdir", isd: cfg.out.isd}),
				"PUBDIR=" + cryptoVotingDir(voter, outConfig{base: "/workdir", isd: cfg.out.isd}),
				"CONTAINER_NAME=" + cfg.container,
			}
			if err := cmd.Run(); err != nil {
				return err
			}
			partFiles = append(partFiles,
				filepath.Join(cryptoVotingDir(voter, cfg.out), "ISD-B1-S1.regular.trc"),
				filepath.Join(cryptoVotingDir(voter, cfg.out), "ISD-B1-S1.sensitive.trc"),
			)
		}

		err = trcs.RunCombine(partFiles, pldName,
			filepath.Join(trcDir(isd, cfg.out), fmt.Sprintf("ISD%d-B1-S1.trc", isd)), "")
		if err != nil {
			return serrors.WrapStr("failed to combine TRCs", err, "isd", isd)
		}
	}
	return nil
}

func setupOpenSSLConfigs(cfg config) error {
	// Create templates in a temporary directory.
	tmpDir, err := ioutil.TempDir("", "testcrypto-configs")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	confs := []string{
		"basic_conf",
		"sensitive_conf",
		"regular_conf",
		"root_conf",
		"ca_conf",
		"as_conf",
	}
	cmd := exec.Command("sh", "-c", withLib(strings.Join(confs, " && "), cfg.lib))
	cmd.Dir = tmpDir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	// Load openssl config templates.
	templates := make(map[string]*template.Template)
	cfgFiles := []string{
		"basic.cnf",
		"sensitive-voting.cnf",
		"regular-voting.cnf",
		"cp-root.cnf",
		"cp-ca.cnf",
		"cp-as.cnf",
	}
	for _, name := range cfgFiles {
		t, err := template.ParseFiles(filepath.Join(tmpDir, name))
		if err != nil {
			return serrors.WithCtx(err, "file", name)
		}
		templates[name] = t
	}

	// Define a struct that contains the templated data.
	type Data struct {
		Country            string
		State              string
		Location           string
		Organization       string
		OrganizationalUnit string
		ISDAS              string
		ShortOrg           string
	}

	for ia, d := range cfg.topo.ASes {
		files := map[string]*template.Template{
			filepath.Join(cryptoASDir(ia, cfg.out), cfgFiles[0]): templates[cfgFiles[0]],
			filepath.Join(cryptoASDir(ia, cfg.out), cfgFiles[5]): templates[cfgFiles[5]],
		}
		if d.Issuing {
			files[filepath.Join(cryptoCADir(ia, cfg.out), cfgFiles[0])] = templates[cfgFiles[0]]
			files[filepath.Join(cryptoCADir(ia, cfg.out), cfgFiles[3])] = templates[cfgFiles[3]]
			files[filepath.Join(cryptoCADir(ia, cfg.out), cfgFiles[4])] = templates[cfgFiles[4]]
			files[filepath.Join(cryptoCADir(ia, cfg.out), cfgFiles[5])] = templates[cfgFiles[5]]
		}
		if d.Voting {
			files[filepath.Join(cryptoVotingDir(ia, cfg.out), cfgFiles[0])] = templates[cfgFiles[0]]
			files[filepath.Join(cryptoVotingDir(ia, cfg.out), cfgFiles[1])] = templates[cfgFiles[1]]
			files[filepath.Join(cryptoVotingDir(ia, cfg.out), cfgFiles[2])] = templates[cfgFiles[2]]
		}
		for fn, tmpl := range files {
			file, err := os.Create(fn)
			if err != nil {
				return err
			}
			defer file.Close()

			data := Data{
				Country:            "CH",
				State:              "Zürich",
				Location:           "Zürich",
				Organization:       ia.String(),
				OrganizationalUnit: ia.String() + " InfoSec Squad",
				ISDAS:              ia.String(),
				ShortOrg:           ia.String(),
			}
			if err := tmpl.Execute(file, data); err != nil {
				return err
			}
		}
	}
	return nil
}

func prepareDirectories(t topo, out outConfig) error {
	for ia, d := range t.ASes {
		dirs := []string{
			trcDir(ia.I, out),
			keyDir(ia, out),
			certDir(ia, out),
			cryptoASDir(ia, out),
			filepath.Join(out.base, "trcs"),
			filepath.Join(out.base, "certs"),
		}
		if d.Issuing {
			dirs = append(dirs, cryptoCADir(ia, out))
			dirs = append(dirs, cryptoCAClientDir(ia, out))
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
			return serrors.WithCtx(err, "file", trc)
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
			return serrors.WithCtx(err, "file", file)
		}
	}
	return nil
}

func fixPermissions(cfg config) error {
	gid := os.Getegid()
	uid := os.Geteuid()

	c := withLib(`docker_exec "`+
		fmt.Sprintf("chown %d:%d /workdir/*/crypto/*/*.key && ", uid, gid)+
		`chmod 0666 /workdir/*/crypto/*/*.key"`, cfg.lib)
	if cfg.out.isd {
		c = strings.ReplaceAll(c, "workdir/", "workdir/*/")
	}
	cmd := exec.Command("sh", "-c", c)
	cmd.Env = []string{"CONTAINER_NAME=" + cfg.container}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func cleanup(cfg config) error {
	c := withLib(`docker_exec "`+
		`rm -f /workdir/*/crypto/*/cp-*.crt && `+
		`rm -f /workdir/*/crypto/*/regular-*.crt && `+
		`rm -f /workdir/*/crypto/*/sensitive-*.crt && `+
		`rm -f /workdir/*/crypto/*/*.cnf && `+
		`rm -f /workdir/*/crypto/*/*.csr && `+
		`rm -f /workdir/*/crypto/voting/ISD-B1-S1.*.trc && `+
		`rm -f /workdir/*/crypto/voting/*.der && `+
		`rm -f /workdir/*/*.der && `+
		`rm -rf /workdir/*/crypto/*/certificates && `+
		`rm -rf /workdir/*/crypto/*/database"`, cfg.lib)
	if cfg.out.isd {
		c = strings.ReplaceAll(c, "workdir/", "workdir/*/")
	}
	cmd := exec.Command("sh", "-c", c)
	cmd.Env = []string{"CONTAINER_NAME=" + cfg.container}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
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
		return fmt.Sprintf("%s/ISD%d/AS%s", cfg.base, ia.I, ia.A.FileFmt())
	}
	return fmt.Sprintf("%s/AS%s", cfg.base, ia.A.FileFmt())
}

func trcDir(isd addr.ISD, out outConfig) string {
	return fmt.Sprintf("%s/ISD%d/trcs", out.base, isd)
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

func cryptoCAClientDir(ia addr.IA, out outConfig) string {
	return filepath.Join(cryptoCADir(ia, out), "clients")
}

func cryptoVotingDir(ia addr.IA, out outConfig) string {
	return filepath.Join(out.AS(ia), "crypto", "voting")
}

func chainName(ia addr.IA) string {
	return fmt.Sprintf("%s.pem", ia.FileFmt(true))
}

func caCertName(ia addr.IA) string {
	return fmt.Sprintf("%s.ca.crt", ia.FileFmt(true))
}

func rootCertName(ia addr.IA, serial ...int) string {
	if len(serial) == 0 {
		return fmt.Sprintf("%s.root.crt", ia.FileFmt(true))
	}
	return fmt.Sprintf("%s.root.s%d.crt", ia.FileFmt(true), serial[0])
}

func sensitiveCertName(ia addr.IA, serial ...int) string {
	if len(serial) == 0 {
		return fmt.Sprintf("%s.sensitive.crt", ia.FileFmt(true))
	}
	return fmt.Sprintf("%s.sensitive.s%d.crt", ia.FileFmt(true), serial[0])
}

func regularCertName(ia addr.IA, serial ...int) string {
	if len(serial) == 0 {
		return fmt.Sprintf("%s.regular.crt", ia.FileFmt(true))
	}
	return fmt.Sprintf("%s.regular.s%d.crt", ia.FileFmt(true), serial[0])
}

func withLib(cmd, lib string) string {
	return fmt.Sprintf(". %s && %s", lib, cmd)
}

func generalizedTime(t time.Time) string {
	return t.UTC().Format("20060102150405Z")
}
