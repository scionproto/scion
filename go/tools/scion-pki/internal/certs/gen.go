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

package certs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/trust"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runGenCert(args []string) {
	asMap, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		pkicmn.ErrorAndExit("Error: %s\n", err)
	}
	for isd, ases := range asMap {
		iconf, err := conf.LoadIsdConf(pkicmn.GetIsdPath(pkicmn.RootDir, isd))
		if err != nil {
			pkicmn.ErrorAndExit("Error reading isd.ini: %s\n", err)
		}
		// Process cores.
		for _, ia := range ases {
			if !pkicmn.Contains(iconf.Trc.CoreIAs, ia) {
				continue
			}
			if err = genCert(ia, true); err != nil {
				pkicmn.ErrorAndExit("Error generating cert for %s: %s\n", ia, err)
			}
		}
		// Process non-cores.
		for _, ia := range ases {
			if pkicmn.Contains(iconf.Trc.CoreIAs, ia) {
				continue
			}
			if err = genCert(ia, false); err != nil {
				pkicmn.ErrorAndExit("Error generating cert for %s: %s\n", ia, err)
			}
		}
	}
	os.Exit(0)
}

func genCert(ia addr.IA, isIssuer bool) error {
	var err error
	confDir := pkicmn.GetAsPath(pkicmn.RootDir, ia)
	outDir := pkicmn.GetAsPath(pkicmn.OutDir, ia)
	// Check that as.ini exists, otherwise skip directory.
	cpath := filepath.Join(confDir, conf.AsConfFileName)
	if _, err = os.Stat(cpath); os.IsNotExist(err) {
		pkicmn.QuietPrint("Skipping %s. Missing %s\n", confDir, conf.AsConfFileName)
		return nil
	}
	a, err := conf.LoadAsConf(confDir)
	if err != nil {
		return common.NewBasicError("Error loading as.ini", err, "path", cpath)
	}
	if isIssuer && a.IssuerCert == nil {
		return common.NewBasicError(fmt.Sprintf("'%s' section missing from as.ini",
			conf.IssuerSectionName), nil, "path", cpath)
	}
	// Check if file already exists.
	fname := fmt.Sprintf(pkicmn.CertNameFmt, ia.I, ia.A.FileFmt(), a.AsCert.Version)
	_, err = os.Stat(filepath.Join(outDir, pkicmn.CertsDir, fname))
	if err == nil && !pkicmn.Force {
		pkicmn.QuietPrint("%s already exists. Use -f to overwrite.\n", fname)
		return nil
	}
	pkicmn.QuietPrint("Generating Certificate Chain for %s\n", ia)
	// If we are an issuer then we need to generate an issuer cert first.
	var issuerCert *cert.Certificate
	if isIssuer {
		issuerCert, err = genIssuerCert(a.IssuerCert, ia)
		if err != nil {
			return common.NewBasicError("Error generating issuer cert", err, "subject", ia)
		}
	} else {
		issuerCert, err = getIssuerCert(a.AsCert.IssuerIA)
		if err != nil {
			return common.NewBasicError("Error loading issuer cert", err, "subject", ia)
		}
	}
	if issuerCert == nil {
		return common.NewBasicError("Issuer cert not found", nil, "issuer", a.AsCert.Issuer)
	}
	// Generate the AS certificate chain.
	chain, err := genASCert(a.AsCert, ia, issuerCert)
	if err != nil {
		return common.NewBasicError("Error generating cert", err, "subject", ia)
	}
	// Check if out directory exists and if not create it.
	out := filepath.Join(outDir, pkicmn.CertsDir)
	if _, err = os.Stat(out); os.IsNotExist(err) {
		if err = os.MkdirAll(out, 0755); err != nil {
			return common.NewBasicError("Cannot create output dir", err, "dir", out)
		}
	}
	// Write the cert to disk.
	raw, err := chain.JSON(true)
	if err != nil {
		return common.NewBasicError("Error json-encoding cert", err, "subject", ia)
	}
	if err = pkicmn.WriteToFile(raw, filepath.Join(out, fname), 0644); err != nil {
		return common.NewBasicError("Error writing cert", err, "subject", ia)
	}
	return nil
}

// genIssuerCert generates a new issuer certificate according to conf.
func genIssuerCert(issuerConf *conf.IssuerCert, s addr.IA) (*cert.Certificate, error) {
	c, err := genCertCommon(issuerConf.BaseCert, s, trust.IssSigKeyFile)
	if err != nil {
		return nil, err
	}
	c.CanIssue = true
	c.Issuer = s
	if c.Comment == "" {
		c.Comment = fmt.Sprintf("Issuer Certificate for %s version %d.", c.Subject, c.Version)
	}
	issuerKeyPath := filepath.Join(pkicmn.GetAsPath(pkicmn.OutDir, c.Issuer), pkicmn.KeysDir,
		trust.OnKeyFile)
	// Load online root key to sign the certificate.
	issuerKey, err := trust.LoadKey(issuerKeyPath)
	if err != nil {
		return nil, err
	}
	// Sign the certificate.
	currTrcPath := filepath.Join(pkicmn.GetIsdPath(pkicmn.OutDir, s.I), pkicmn.TRCsDir,
		fmt.Sprintf(pkicmn.TrcNameFmt, s.I, c.TRCVersion))
	currTrc, err := trc.TRCFromFile(currTrcPath, false)
	if err != nil {
		return nil, common.NewBasicError("Error reading TRC", err, "path: ", currTrcPath)
	}
	coreAs, ok := currTrc.CoreASes[s]
	if !ok {
		return nil, common.NewBasicError("Issuer of IssuerCert not found in Core ASes of TRC",
			nil, "issuer", s)
	}
	if err = c.Sign(issuerKey, coreAs.OnlineKeyAlg); err != nil {
		return nil, err
	}

	return c, nil
}

// genASCert generates a new AS certificate according to 'conf'.
func genASCert(conf *conf.AsCert, s addr.IA, issuerCert *cert.Certificate) (*cert.Chain, error) {
	c, err := genCertCommon(conf.BaseCert, s, trust.SigKeyFile)
	if err != nil {
		return nil, err
	}
	c.CanIssue = false
	c.Issuer = conf.IssuerIA
	if c.Comment == "" {
		c.Comment = fmt.Sprintf("AS Certificate for %s version %d.", c.Subject, c.Version)
	}
	// Ensure issuer can issue certificates.
	if !issuerCert.CanIssue {
		return nil, common.NewBasicError("Issuer cert not authorized to issue certs.", nil,
			"issuer", c.Issuer, "subject", c.Subject)
	}
	issuerKeyPath := filepath.Join(pkicmn.GetAsPath(pkicmn.OutDir, conf.IssuerIA), pkicmn.KeysDir,
		trust.IssSigKeyFile)
	issuerKey, err := trust.LoadKey(issuerKeyPath)
	if err != nil {
		return nil, err
	}
	// Sign the certificate.
	if err = c.Sign(issuerKey, issuerCert.SignAlgorithm); err != nil {
		return nil, err
	}
	// Create certificate chain.
	chain := &cert.Chain{
		Leaf:   c,
		Issuer: issuerCert,
	}
	if verify {
		err = verifyChain(chain, c.Subject)
		if err != nil {
			fname := fmt.Sprintf(pkicmn.CertNameFmt, c.Subject.I, c.Subject.A, c.Version)
			return nil, common.NewBasicError("Verification FAILED", err, "cert", fname)
		}
	}
	// Write the cert to disk.
	return chain, nil
}

func genCertCommon(bc *conf.BaseCert, s addr.IA, signKeyFname string) (*cert.Certificate, error) {
	// Load signing and decryption keys that will be in the certificate.
	keyDir := filepath.Join(pkicmn.GetAsPath(pkicmn.OutDir, s), pkicmn.KeysDir)
	signKey, err := trust.LoadKey(filepath.Join(keyDir, signKeyFname))
	if err != nil {
		return nil, err
	}
	signPub := common.RawBytes(ed25519.PrivateKey(signKey).Public().(ed25519.PublicKey))
	decKey, err := trust.LoadKey(filepath.Join(keyDir, trust.DecKeyFile))
	if err != nil {
		return nil, err
	}
	var decKeyFixed, decPub [32]byte
	copy(decKeyFixed[:], decKey)
	curve25519.ScalarBaseMult(&decPub, &decKeyFixed)
	// Determine issuingTime and calculate expiration time from validity.
	issuingTime := bc.IssuingTime
	if issuingTime == 0 {
		issuingTime = uint64(time.Now().Unix())
	}
	expirationTime := issuingTime + uint64(bc.Validity.Seconds())
	return &cert.Certificate{
		Comment:        bc.Comment,
		SubjectSignKey: signPub,
		SignAlgorithm:  bc.SignAlgorithm,
		SubjectEncKey:  decPub[:],
		EncAlgorithm:   bc.EncAlgorithm,
		Subject:        s,
		IssuingTime:    issuingTime,
		ExpirationTime: expirationTime,
		Version:        bc.Version,
		TRCVersion:     bc.TRCVersion,
	}, nil
}

// getIssuerCert returns the newest issuer certificate (if any).
func getIssuerCert(issuer addr.IA) (*cert.Certificate, error) {
	fnames, err := filepath.Glob(fmt.Sprintf("%s/*.crt",
		filepath.Join(pkicmn.GetAsPath(pkicmn.OutDir, issuer), pkicmn.CertsDir)))
	if err != nil {
		return nil, err
	}
	var issuerCert *cert.Certificate
	for _, fname := range fnames {
		raw, err := ioutil.ReadFile(fname)
		if err != nil {
			return nil, err
		}
		chain, err := cert.ChainFromRaw(raw, false)
		if err != nil {
			return nil, err
		}
		if issuerCert == nil || chain.Issuer.Version > issuerCert.Version {
			issuerCert = chain.Issuer
		}
	}
	return issuerCert, nil
}
