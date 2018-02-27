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
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/trust"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/keys"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runGenCert(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	top, err := pkicmn.ProcessSelector(args[0], args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		cmd.Usage()
		os.Exit(2)
	}
	// In the first walk, only process core ASes under <top>/
	if err := filepath.Walk(top, getWalker(true)); err != nil && err != filepath.SkipDir {
		base.ErrorAndExit("%s\n", err)
	}
	// In the second walk, process everything that hasn't been processed yet under <top>/
	if err := filepath.Walk(top, getWalker(false)); err != nil && err != filepath.SkipDir {
		base.ErrorAndExit("%s\n", err)
	}
}

func getWalker(core bool) filepath.WalkFunc {
	return func(path string, info os.FileInfo, visitError error) error {
		if visitError != nil {
			return visitError
		}
		// If not an AS directory, keep walking.
		if !info.IsDir() || !strings.HasPrefix(info.Name(), "AS") {
			return nil
		}
		var err error
		// Check that cert.ini exists, otherwise skip directory.
		cpath := filepath.Join(path, confFile)
		if _, err = os.Stat(cpath); os.IsNotExist(err) {
			return filepath.SkipDir
		}
		// Check that core-cert.ini exists, otherwise skip directory if walking core ASes.
		ccpath := filepath.Join(path, coreConfFile)
		if _, err = os.Stat(ccpath); os.IsNotExist(err) && core {
			return filepath.SkipDir
		}
		// Skip AS if we are processing the non-core ASes and there is a core-cert.ini
		if err == nil && !core {
			return filepath.SkipDir
		}
		conf, err := loadCertConf(cpath)
		if err != nil {
			return common.NewBasicError("Error loading cert.ini", err, "path", cpath)
		}
		fmt.Println("Generating Certificate Chain for", conf.Subject)
		// Generate keys if specified
		if genKeys {
			fmt.Println("Generating keys for", conf.Subject)
			err = keys.GenAll(filepath.Join(path, "keys"), core)
			if err != nil {
				return err
			}
		}
		// If we are core then we need to generate a core AS cert first.
		var issuerCert *cert.Certificate
		if core {
			issuerCert, err = genIssuerCert(conf.issuerIA, ccpath)
		} else {
			issuerCert, err = getIssuerCert(conf.issuerIA)
		}
		if err != nil {
			return err
		}
		if issuerCert == nil {
			return common.NewBasicError("Issuer cert not found", err, "issuer", conf.Issuer)
		}
		// Generate the AS certificate chain.
		chain, err := genASCert(conf, issuerCert)
		if err != nil {
			return common.NewBasicError("Error generating cert", err, "subject", conf.Subject)
		}
		// Check if out directory exists and if not create it.
		dir := filepath.Join(path, "certs")
		if _, err = os.Stat(dir); os.IsNotExist(err) {
			if err = os.MkdirAll(dir, 0755); err != nil {
				return common.NewBasicError("Cannot create output dir", err, "path", path)
			}
		}
		// Write the cert to disk.
		subject := chain.Leaf.Subject
		fname := fmt.Sprintf(pkicmn.CertNameFmt, subject.I, subject.A, chain.Leaf.Version)
		raw, err := chain.JSON(true)
		if err != nil {
			return common.NewBasicError("Error json-encoding cert", err, "subject", conf.Subject)
		}
		if err = pkicmn.WriteToFile(raw, filepath.Join(dir, fname), 0644); err != nil {
			return common.NewBasicError("Error writing cert", err, "subject", conf.Subject)
		}
		// Skip the rest of this directory.
		return filepath.SkipDir
	}
}

func genCertCommon(conf *certConf) (*cert.Certificate, error) {
	// Load signing and decryption keys that will be in the certificate.
	// FIXME(shitz): CoreAS keys should be different from AS keys.
	keyDir := filepath.Join(path(conf.subjectIA), "keys")
	signKey, err := trust.LoadKey(filepath.Join(keyDir, trust.SigKeyFile))
	if err != nil {
		return nil, err
	}
	signPub := common.RawBytes(ed25519.PrivateKey(signKey).Public().(ed25519.PublicKey))
	decKey, err := trust.LoadKey(filepath.Join(keyDir, trust.DecKeyFile))
	if err != nil {
		return nil, err
	}
	decKeyFixed := new([32]byte)
	copy(decKeyFixed[:], decKey)
	decPub := new([32]byte)
	curve25519.ScalarBaseMult(decPub, decKeyFixed)
	// Determine issuingTime and calculate expiration time from validity.
	issuingTime := uint64(time.Now().Unix())
	expirationTime := issuingTime + conf.Validity*24*60*60
	c := &cert.Certificate{
		CanIssue:       conf.CanIssue,
		Comment:        conf.Comment,
		SubjectSignKey: signPub,
		SignAlgorithm:  conf.SignAlgorithm,
		SubjectEncKey:  decPub[:],
		EncAlgorithm:   conf.EncAlgorithm,
		Issuer:         conf.issuerIA,
		Subject:        conf.subjectIA,
		IssuingTime:    issuingTime,
		ExpirationTime: expirationTime,
		Version:        conf.Version,
		TRCVersion:     conf.TRCVersion,
	}

	return c, nil
}

// genCoreASCert generates a new core AS certificate according to conf.
func genCoreASCert(conf *certConf) (*cert.Certificate, error) {
	c, err := genCertCommon(conf)
	if err != nil {
		return nil, err
	}
	if c.Comment == "" {
		c.Comment = fmt.Sprintf("Core AS Certificate for %s version %d.", c.Subject, c.Version)
	}
	// For core AS certificates issuer == subject.
	if !c.Issuer.Eq(c.Subject) {
		return nil, common.NewBasicError("Subject must match Issuer for Core AS cert.", nil,
			"subject", c.Subject, "issuer", c.Issuer)
	}
	issuerKeyPath := filepath.Join(path(c.Issuer), "keys", trust.OnKeyFile)
	// Load online root key to sign the certificate.
	issuerKey, err := trust.LoadKey(issuerKeyPath)
	if err != nil {
		return nil, err
	}
	// Sign the certificate.
	// FIXME(shitz): The signing algorithm should be supplied or read from the TRC.
	if err = c.Sign(issuerKey, crypto.Ed25519); err != nil {
		return nil, err
	}
	return c, nil
}

// genASCert generates a new AS certificate according to 'conf'.
func genASCert(conf *certConf, issuerCert *cert.Certificate) (*cert.Chain, error) {
	c, err := genCertCommon(conf)
	if err != nil {
		return nil, err
	}
	if c.Comment == "" {
		c.Comment = fmt.Sprintf("AS Certificate for %s version %d.", c.Subject, c.Version)
	}
	// Ensure issuer can issue certificates.
	if !issuerCert.CanIssue {
		return nil, common.NewBasicError("Issuer cert not authorized to issue new certs.", nil,
			"issuer", c.Issuer)
	}
	issuerKeyPath := filepath.Join(path(issuerCert.Issuer), "keys", trust.SigKeyFile)
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
		Leaf: c,
		Core: issuerCert,
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

// getIssuerCert returns the newest core certificate of issuer (if any).
func getIssuerCert(issuer *addr.ISD_AS) (*cert.Certificate, error) {
	fnames, err := filepath.Glob(fmt.Sprintf("%s/*.crt",
		filepath.Join(path(issuer), "certs")))
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
		if issuerCert == nil || chain.Core.Version > issuerCert.Version {
			issuerCert = chain.Core
		}
	}
	return issuerCert, nil
}

func genIssuerCert(issuer *addr.ISD_AS, ccpath string) (*cert.Certificate, error) {
	coreConf, err := loadCertConf(ccpath)
	if err != nil {
		return nil, common.NewBasicError("Error loading core-cert.ini", err, "subject", issuer)
	}
	issuerCert, err := getIssuerCert(issuer)
	if err != nil {
		return nil, err
	}
	// We already have a core AS certificate of the specified version.
	if issuerCert != nil && issuerCert.Version >= coreConf.Version {
		return issuerCert, nil
	}
	// Need to generate a new core AS certificate.
	issuerCert, err = genCoreASCert(coreConf)
	if err != nil {
		return nil, common.NewBasicError("Error generating core AS cert", err, "subject", issuer)
	}
	return issuerCert, nil
}

func path(ia *addr.ISD_AS) string {
	return filepath.Join(pkicmn.RootDir, fmt.Sprintf("ISD%d/AS%d", ia.I, ia.A))
}
