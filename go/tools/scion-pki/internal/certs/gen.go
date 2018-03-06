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
	"github.com/scionproto/scion/go/lib/crypto"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/trust"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runGenCert(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	isdDirs, asDirs, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		cmd.Usage()
		os.Exit(2)
	}
	for i, isdDir := range isdDirs {
		tconf, err := conf.LoadTrcConf(isdDir)
		if err != nil {
			base.ErrorAndExit("Error reading isd.ini: %s\n", err)
		}
		cores, ases := pkicmn.FilterASDirs(asDirs[i], tconf.CoreIAs)
		for _, dir := range cores {
			if err = genCert(dir, true); err != nil {
				base.ErrorAndExit("Error generating %s: %s\n",
					filepath.Join(dir, conf.AsConfFileName), err)
			}
		}
		for _, dir := range ases {
			if err = genCert(dir, false); err != nil {
				base.ErrorAndExit("Error generating %s: %s\n",
					filepath.Join(dir, conf.AsConfFileName), err)
			}
		}
	}
}

func genCert(dir string, core bool) error {
	var err error
	// Check that as.ini exists, otherwise skip directory.
	cpath := filepath.Join(dir, conf.AsConfFileName)
	if _, err = os.Stat(cpath); os.IsNotExist(err) {
		return nil
	}
	a, err := conf.LoadAsConf(dir)
	if err != nil {
		return common.NewBasicError("Error loading as.ini", err, "path", cpath)
	}
	if core && a.CC == nil {
		return common.NewBasicError("'%s' section missing from as.ini", nil, "path", cpath)
	}
	fmt.Println("Generating Certificate Chain for", a.C.Subject)
	// If we are core then we need to generate a core AS cert first.
	var issuerCert *cert.Certificate
	if core {
		issuerCert, err = genCoreASCert(a.CC)
	} else {
		issuerCert, err = getIssuerCert(a.C.IssuerIA)
	}
	if err != nil {
		return common.NewBasicError("Error loading issuer cert", err, "subject", a.C.Subject)
	}
	if issuerCert == nil {
		return common.NewBasicError("Issuer cert not found", err, "issuer", a.C.Issuer)
	}
	// Generate the AS certificate chain.
	chain, err := genASCert(a.C, issuerCert)
	if err != nil {
		return common.NewBasicError("Error generating cert", err, "subject", a.C.Subject)
	}
	// Check if out directory exists and if not create it.
	out := filepath.Join(dir, "certs")
	if _, err = os.Stat(out); os.IsNotExist(err) {
		if err = os.MkdirAll(out, 0755); err != nil {
			return common.NewBasicError("Cannot create output dir", err, "dir", out)
		}
	}
	// Write the cert to disk.
	subject := chain.Leaf.Subject
	fname := fmt.Sprintf(pkicmn.CertNameFmt, subject.I, subject.A, chain.Leaf.Version)
	raw, err := chain.JSON(true)
	if err != nil {
		return common.NewBasicError("Error json-encoding cert", err, "subject", a.C.Subject)
	}
	if err = pkicmn.WriteToFile(raw, filepath.Join(out, fname), 0644); err != nil {
		return common.NewBasicError("Error writing cert", err, "subject", a.C.Subject)
	}
	return nil
}

func genCertCommon(conf *conf.Cert, signKeyFname string) (*cert.Certificate, error) {
	// Load signing and decryption keys that will be in the certificate.
	keyDir := filepath.Join(pkicmn.GetPath(conf.SubjectIA), "keys")
	signKey, err := trust.LoadKey(filepath.Join(keyDir, signKeyFname))
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
		Issuer:         conf.IssuerIA,
		Subject:        conf.SubjectIA,
		IssuingTime:    issuingTime,
		ExpirationTime: expirationTime,
		Version:        conf.Version,
		TRCVersion:     conf.TRCVersion,
	}

	return c, nil
}

// genCoreASCert generates a new core AS certificate according to conf.
func genCoreASCert(conf *conf.Cert) (*cert.Certificate, error) {
	c, err := genCertCommon(conf, trust.CoreSigKeyFile)
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
	issuerKeyPath := filepath.Join(pkicmn.GetPath(c.Issuer), "keys", trust.OnKeyFile)
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
func genASCert(conf *conf.Cert, issuerCert *cert.Certificate) (*cert.Chain, error) {
	c, err := genCertCommon(conf, trust.SigKeyFile)
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
	issuerKeyPath := filepath.Join(pkicmn.GetPath(issuerCert.Issuer), "keys", trust.CoreSigKeyFile)
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
		filepath.Join(pkicmn.GetPath(issuer), "certs")))
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
