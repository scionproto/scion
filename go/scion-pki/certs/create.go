// Copyright 2021 Anapaya Systems
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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/app/flag"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/file"
	"github.com/scionproto/scion/go/scion-pki/key"
)

var (
	extendedKeyUsagesByType = map[cppki.CertType]pkix.Extension{
		cppki.AS: extendedKeyUsages(
			cppki.OIDExtKeyUsageServerAuth,
			cppki.OIDExtKeyUsageClientAuth,
			cppki.OIDExtKeyUsageTimeStamping,
		),
		// cppki.CA does not need extended key usage.
		cppki.Root: extendedKeyUsages(
			cppki.OIDExtKeyUsageRoot,
			cppki.OIDExtKeyUsageTimeStamping,
		),
		cppki.Regular: extendedKeyUsages(
			cppki.OIDExtKeyUsageRegular,
			cppki.OIDExtKeyUsageTimeStamping,
		),
		cppki.Sensitive: extendedKeyUsages(
			cppki.OIDExtKeyUsageSensitive,
			cppki.OIDExtKeyUsageTimeStamping,
		),
	}

	certTemplateByType = map[cppki.CertType]x509.Certificate{
		cppki.AS: {
			Version:  3,
			KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageTimeStamping,
			},
		},
		cppki.CA: {
			Version:               3,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
		},
		cppki.Root: {
			Version:  3,
			KeyUsage: x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageTimeStamping,
			},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{
				cppki.OIDExtKeyUsageRoot,
			},
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
			MaxPathLenZero:        true,
		},
		cppki.Regular: {
			Version: 3,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageTimeStamping,
			},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{
				cppki.OIDExtKeyUsageRegular,
			},
		},
		cppki.Sensitive: {
			Version: 3,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageTimeStamping,
			},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{
				cppki.OIDExtKeyUsageSensitive,
			},
		},
	}
)

// NewCreateCmd returns a cobra command that generates new certificates.
func newCreateCmd(pather command.Pather) *cobra.Command {
	now := time.Now().UTC()
	var flags struct {
		csr         bool
		profile     string
		commonName  string
		notBefore   flag.Time
		notAfter    flag.Time
		ca          string
		caKey       string
		existingKey string
		curve       string
		bundle      bool
		force       bool
	}
	flags.notBefore = flag.Time{
		Time:    now,
		Current: now,
	}
	flags.notAfter = flag.Time{
		Current: now,
		Default: "depends on profile",
	}

	var cmd = &cobra.Command{
		Use:   "create [flags] <subject-template> <cert-file> <key-file>",
		Short: "Create a certificate or certificate signing request",
		Example: fmt.Sprintf(`  %[1]s create --profile cp-root subject.tmpl cp-root.crt cp-root.key
  %[1]s create --ca cp-ca.crt --ca-key cp-ca.key subject.tmpl chain.pem cp-as.key
  %[1]s create --csr subject.tmpl chain.csr cp-as.key`,
			pather.CommandPath(),
		),
		Long: `'create' generates a certificate or a certificate signing request (CSR).

Then command takes the following positional arguments:
- <subject-template> is the template for the certificate subject distinguished name.
- <crt-file> is the file path where the certificate or certificate requests is
  written to. The parent directory must exist and must be writable.
- <key-file> is the file path where the fresh private key is written to. The
  parent directory must exist and must be writable.

By default, the command creates a SCION control-plane PKI AS certificate. Another
certificate type can be selected by providing the --profile flag. If a certificate
chain is desired, specify the --bundle flag.

A fresh key is created in the provided <key-file>, unless the --key flag is set.
If the --key flag is set, an existing private key is used and the <key-file> is
ignored.

The --ca and --ca-key flags are required if a AS certificate or CA certificate
is being created. Otherwise, they are not allowed.

The --not-before and --not-after flags can either be a timestamp or a relative
time offset from the current time.

A timestamp can be provided in two different formats: unix timestamp and
RFC 3339 timestamp. For example, 2021-06-24T12:01:02Z represents 1 minute and 2
seconds after the 12th hour of June 26th, 2021 in UTC.

The relative time offset can be formated as a time duration string with the
following units: y, w, d, h, m, s. Negative offsets are also allowed. For
example, -1h indicates the time of tool invocation minus one hour. Note that
--not-after is relative to the current time if a relative time offset is used,
and not to --not-before.

The <subject-template> is the template for the distinguished name of the
requested certificate and must either be a x.509 certificate or a JSON file.
The common name can be overridden by supplying the --common-name flag.

If it is a x.509 certificate, the subject of the template is used as the subject
of the created certificate or certificate chain request.

A valid example for a JSON formatted template:
` + subjectHelp,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 2 && flags.existingKey == "" {
				return serrors.New("positional key file is required")
			}
			ct, err := parseCertType(flags.profile)
			if err != nil {
				return serrors.WrapStr("parsing profile", err)
			}
			subject, err := createSubject(args[0])
			if err != nil {
				return serrors.WrapStr("creating subject", err)
			}
			if flags.commonName != "" {
				subject.CommonName = flags.commonName
			}

			// Only check that the flags are set appropriately here.
			// Do the actual parsing after the usage help message is silenced.
			var loadCA bool
			isSelfSigned := (ct == cppki.Root || ct == cppki.Regular || ct == cppki.Sensitive)
			withCA := (flags.ca != "" || flags.caKey != "")
			switch {
			case flags.csr && withCA:
				return serrors.New("CA information set for CSR")
			case !flags.csr && isSelfSigned && withCA:
				return serrors.New("CA information set for self-signed certificate")
			default:
				loadCA = !isSelfSigned
			}

			cmd.SilenceUsage = true

			var privKey key.PrivateKey
			var encodedKey []byte
			if flags.existingKey != "" {
				if privKey, err = key.LoadPrivateKey(flags.existingKey); err != nil {
					return serrors.WrapStr("loading existing private key", err)
				}
			} else {
				if privKey, err = key.GeneratePrivateKey(flags.curve); err != nil {
					return serrors.WrapStr("creating fresh private key", err)
				}
				if encodedKey, err = key.EncodePEMPrivateKey(privKey); err != nil {
					return serrors.WrapStr("encoding fresh private key", err)
				}
			}

			var caCertRaw []byte
			var caCert *x509.Certificate
			var caKey key.PrivateKey
			if loadCA {
				if caCertRaw, err = ioutil.ReadFile(flags.ca); err != nil {
					return serrors.WrapStr("read CA certificate", err)
				}
				if caCert, err = parseCertificate(caCertRaw); err != nil {
					return serrors.WrapStr("parsing CA certificate", err)
				}
				if caKey, err = key.LoadPrivateKey(flags.caKey); err != nil {
					return serrors.WrapStr("loading CA private key", err)
				}
			}

			if flags.csr {
				csr, err := CreateCSR(ct, subject, privKey)
				if err != nil {
					return serrors.WrapStr("creating CSR", err)
				}
				encodedCSR := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csr,
				})
				if encodedCSR == nil {
					panic("failed to encode CSR")
				}
				csrFile := args[1]
				err = file.WriteFile(csrFile, encodedCSR, 0644, file.WithForce(flags.force))
				if err != nil {
					return serrors.WrapStr("writing CSR", err)
				}
				fmt.Printf("CSR successfully written to %q\n", csrFile)
			} else {
				cert, err := CreateCertificate(CertParams{
					Type:      ct,
					Subject:   subject,
					Key:       privKey,
					NotBefore: flags.notBefore.Time,
					NotAfter:  notAfterFromFlags(ct, flags.notBefore, flags.notAfter),
					CAKey:     caKey,
					CACert:    caCert,
				})
				if err != nil {
					return serrors.WrapStr("creating certificate", err)
				}
				encodedCert := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert,
				})
				if encodedCert == nil {
					panic("failed to encode CSR")
				}
				if flags.bundle {
					fmt.Println("Bundling certificate as certificate chain")
					encodedCert = append(encodedCert, caCertRaw...)
				}
				certFile := args[1]
				err = file.WriteFile(certFile, encodedCert, 0644, file.WithForce(flags.force))
				if err != nil {
					return serrors.WrapStr("writing certificate", err)
				}
				fmt.Printf("Certificate successfully written to %q\n", certFile)
			}

			if encodedKey != nil {
				keyFile := args[2]
				if err := file.CheckDirExists(filepath.Dir(keyFile)); err != nil {
					return serrors.WrapStr("checking that directory of private key exists", err)
				}
				err := file.WriteFile(keyFile, encodedKey, 0600, file.WithForce(flags.force))
				if err != nil {
					return serrors.WrapStr("writing private key", err)
				}
				fmt.Printf("Private key successfully written to %q\n", keyFile)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&flags.csr, "csr", false,
		"Generate a certificate signign request instead of a certificate",
	)
	cmd.Flags().StringVar(&flags.profile, "profile", "cp-as",
		"The type of certificate to generate (cp-as|cp-ca|cp-root|sensitive-voting|regular-voting)",
	)
	cmd.Flags().Var(&flags.notBefore, "not-before",
		`The NotBefore time of the certificate. Can either be a timestamp or an offset.

If the value is a timestamp, it is expected to either be an RFC 3339 formatted
timestamp or a unix timestamp. If the value is a duration, it is used as the
offset from the current time.`,
	)
	cmd.Flags().Var(&flags.notAfter, "not-after",
		`The NotAfter time of the certificate. Can either be a timestamp or an offset.

If the value is a timestamp, it is expected to either be an RFC 3339 formatted
timestamp or a unix timestamp. If the value is a duration, it is used as the
offset from the current time.`,
	)
	cmd.Flags().StringVar(&flags.commonName, "common-name", "",
		"The common name that replaces the common name in the subject template",
	)
	cmd.Flags().StringVar(&flags.ca, "ca", "",
		"The path to the issuer certificate",
	)
	cmd.Flags().StringVar(&flags.caKey, "ca-key", "",
		"The path to the issuer private key used to sign the new certificate",
	)
	cmd.Flags().StringVar(&flags.existingKey, "key", "",
		"The path to the existing private key to use instead of creating a new one",
	)
	cmd.Flags().StringVar(&flags.curve, "curve", "P-256",
		"The elliptic curve to use (P-256|P-384|P-521)",
	)
	cmd.Flags().BoolVar(&flags.bundle, "bundle", false,
		"Bundle the certificate with the issuer certificate as a certificate chain",
	)
	cmd.Flags().BoolVar(&flags.force, "force", false,
		"Force overwritting existing files",
	)

	return cmd
}

func notAfterFromFlags(ct cppki.CertType, notBefore, notAfter flag.Time) time.Time {
	if !notAfter.Time.IsZero() {
		return notAfter.Time
	}
	switch ct {
	case cppki.Sensitive, cppki.Regular:
		return notBefore.Time.AddDate(5, 0, 0)
	case cppki.Root:
		return notBefore.Time.AddDate(1, 0, 0)
	case cppki.CA:
		return notBefore.Time.AddDate(0, 0, 11)
	default:
		return notBefore.Time.AddDate(0, 0, 3)
	}
}

func parseCertType(input string) (cppki.CertType, error) {
	switch strings.ToLower(input) {
	case cppki.AS.String():
		return cppki.AS, nil
	case cppki.CA.String():
		return cppki.CA, nil
	case cppki.Root.String():
		return cppki.Root, nil
	case cppki.Regular.String():
		return cppki.Regular, nil
	case cppki.Sensitive.String():
		return cppki.Sensitive, nil
	default:
		return 0, serrors.New("unsupported", "type", input)
	}
}

func createSubject(tmpl string) (pkix.Name, error) {
	raw, err := ioutil.ReadFile(tmpl)
	if err != nil {
		return pkix.Name{}, err
	}
	// Check if template is a x509 certificate.
	cert, err := parseCertificate(raw)
	if err == nil {
		s := cert.Subject
		s.ExtraNames = cert.Subject.Names
		return s, nil
	}

	// Assume template is a json file.
	var vars SubjectVars
	if err := json.Unmarshal(raw, &vars); err != nil {
		return pkix.Name{}, err
	}
	return subjectFromVars(vars)
}

func parseCertificate(raw []byte) (*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, serrors.New("empty")
	}
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return nil, serrors.New("error extracting PEM block")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
	return nil, serrors.New("no certificate found")
}

func CreateCSR(certType cppki.CertType, subject pkix.Name, priv key.PrivateKey) ([]byte, error) {
	skid, err := subjectKeyID(priv.Public())
	if err != nil {
		return nil, err
	}

	var extensions []pkix.Extension
	switch certType {
	case cppki.AS:
		extensions = []pkix.Extension{
			keyUsage(),
			extendedKeyUsagesByType[cppki.AS],
			skid,
		}
	case cppki.CA:
		extensions = []pkix.Extension{
			basicConstraints(0),
			keyUsageCertSign(),
			skid,
		}
	case cppki.Root:
		extensions = []pkix.Extension{
			basicConstraints(1),
			keyUsageCertSign(),
			extendedKeyUsagesByType[cppki.Root],
			skid,
		}
	case cppki.Regular:
		extensions = []pkix.Extension{
			extendedKeyUsagesByType[cppki.Regular],
			skid,
		}
	case cppki.Sensitive:
		extensions = []pkix.Extension{
			extendedKeyUsagesByType[cppki.Sensitive],
			skid,
		}
	default:
		return nil, serrors.New("not supported", "type", certType)
	}
	return x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject:    subject,
			Extensions: extensions,
		},
		priv,
	)
}

type CertParams struct {
	Type      cppki.CertType
	Subject   pkix.Name
	Key       key.PrivateKey
	NotBefore time.Time
	NotAfter  time.Time

	CACert *x509.Certificate
	CAKey  key.PrivateKey
}

func CreateCertificate(params CertParams) ([]byte, error) {
	tmpl, ok := certTemplateByType[params.Type]
	if !ok {
		return nil, serrors.New("certificate type not supported", "type", params.Type)
	}
	serial := make([]byte, 20)
	if _, err := rand.Read(serial); err != nil {
		return nil, serrors.WrapStr("creating random serial number", err)
	}
	skid, err := cppki.SubjectKeyID(params.Key.Public())
	if err != nil {
		return nil, serrors.WrapStr("computing subject key ID", err)
	}

	tmpl.SerialNumber = big.NewInt(0).SetBytes(serial)
	tmpl.SubjectKeyId = skid
	tmpl.Subject = params.Subject
	tmpl.NotBefore = params.NotBefore
	tmpl.NotAfter = params.NotAfter
	if ca := params.CACert; ca != nil {
		caValididty := cppki.Validity{NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
		tmplValididty := cppki.Validity{NotBefore: tmpl.NotBefore, NotAfter: tmpl.NotAfter}
		if !caValididty.Covers(tmplValididty) {
			return nil, serrors.New("certificate validity not covered by CA certificate",
				"ca_validity", caValididty,
				"certificate_validity", tmplValididty,
			)
		}

		tmpl.AuthorityKeyId = params.CACert.SubjectKeyId
	} else {
		params.CACert = &tmpl
		params.CAKey = params.Key
	}
	cert, err := x509.CreateCertificate(
		rand.Reader,
		&tmpl,
		params.CACert,
		params.Key.Public(),
		params.CAKey,
	)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, serrors.WrapStr("parsing new certificate", err)
	}
	ct, err := cppki.ValidateCert(parsed)
	if err != nil {
		return nil, serrors.WrapStr("validating new certificate", err)
	}
	if ct != params.Type {
		return nil, serrors.New("new certificate of invalid type", "type", ct)
	}
	return cert, nil
}

func basicConstraints(pathLen int) pkix.Extension {
	val, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{
		IsCA:       true,
		MaxPathLen: pathLen,
	})
	if err != nil {
		panic(err)
	}
	return pkix.Extension{
		Id:       cppki.OIDExtensionBasicConstraints,
		Critical: true,
		Value:    val,
	}
}

func keyUsageCertSign() pkix.Extension {
	// 0x04 corresponds to x509.KeyUsageCertSign
	val, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x04}, BitLength: 1})
	if err != nil {
		panic(err)
	}
	return pkix.Extension{
		Id:       cppki.OIDExtensionKeyUsage,
		Critical: true,
		Value:    val,
	}
}

func extendedKeyUsages(usages ...asn1.ObjectIdentifier) pkix.Extension {
	val, err := asn1.Marshal(usages)
	if err != nil {
		panic(err)
	}
	return pkix.Extension{
		Id:    cppki.OIDExtensionExtendedKeyUsage,
		Value: val,
	}
}
