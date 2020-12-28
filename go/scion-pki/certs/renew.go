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

package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/pkg/app/feature"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
)

type subjectVars struct {
	CommonName         string  `json:"common_name,omitempty"`
	Country            string  `json:"country,omitempty"`
	ISDAS              addr.IA `json:"isd_as,omitempty"`
	Locality           string  `json:"locality,omitempty"`
	Organization       string  `json:"organization,omitempty"`
	OrganizationalUnit string  `json:"organizational_unit,omitempty"`
	PostalCode         string  `json:"postal_code,omitempty"`
	Province           string  `json:"province,omitempty"`
	SerialNumber       string  `json:"serial_number,omitempty"`
	StreetAddress      string  `json:"street_address,omitempty"`
}

func newRenewCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		keyFile           string
		outFile           string
		templateFile      string
		transportCertFile string
		transportKeyFile  string
		trcFilePath       string

		dispatcherPath string
		daemon         string
		listen         net.IP
		timeout        time.Duration

		features []string
	}

	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew AS certificate",
		Args:  cobra.MaximumNArgs(1),
		Example: fmt.Sprintf(`  %[1]s renew
	--key cp-as.key \
	--transportcert ISD1-ASff00_0_112.pem \
	--transportkey cp-as.key \
	--trc ISD1-B1-S1.trc

  %[1]s renew
	--key fresh.key \
	--transportcert ISD1-ASff00_0_112.pem \
	--transportkey cp-as.key \
	--trc ISD1-B1-S1.trc \
	--template csr.json \
	  1-ff00:0:110
		`, pather.CommandPath()),
		Long: `'renew' sends a certificate chain renewal request to the CA control service.

The transport certificate chain and key are used to sign the renewal requests.
In order for the CA to be able to verify the request, the chain must already
be known to the CA. Either through an out-of-bound bootstrapping mechanism where
the CA preloads it, or from a previous certificate chain renewal.

The TRC is used to validate and verify the renewed certificate chain. Ensure
that it contains the root certificate that the CA is using.

The renewed certificate chain is written to the file system, if it is verifiable
with the supplied TRC. In case the out flag is not specified, the chain is
written to 'ISDx-ASy.s.pem' in the same directory as the transport certificate
chain, where x is the ISD number, y is the AS number, and s is the hex encoded
serial number of the AS certificate in the renewed certificate chain. If the
chain verification against the TRC fails, the renewed certificate chain is
written to the out file with the suffix '.unverified' and the command fails.

The positional argument is the ISD-AS of the CA where the renewal request is
sent to. If it is not set, the ISD-AS is extracted from the transport
certificate chain.

Unless a template is specified, the subject of the transport certificate chain
is used as the subject for the renewal request.

The template is expressed in JSON. A valid example:

  {
    "common_name": "1-ff00:0:110 AS certificate",
    "country": "CH",
    "isd_as": "1-ff00:0:110"
  }

All configurable fields with their type are defined by the following JSON
schema. For more information on JSON schemas, see https://json-schema.org/.

  {
    "type": "object",
    "properties": {
      "isd_as":              { "type": "string" },
      "common_name":         { "type": "string" },
      "country":             { "type": "string" },
      "locality":            { "type": "string" },
      "organization":        { "type": "string" },
      "organizational_unit": { "type": "string" },
      "postal_code":         { "type": "string" },
      "province":            { "type": "string" },
      "serial_number":       { "type": "string" },
      "street_address":      { "type": "string" },
    },
    "required": ["isd_as"]
  }
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var ca addr.IA
			if len(args) != 0 {
				var err error
				if ca, err = addr.IAFromString(args[0]); err != nil {
					return err
				}
			}
			cmd.SilenceUsage = true

			log.Setup(log.Config{Console: log.ConsoleConfig{Level: "crit"}})

			trc, err := loadTRC(flags.trcFilePath)
			if err != nil {
				return err
			}
			chain, transportCA, err := loadChain(trc, flags.transportCertFile)
			if err != nil {
				return err
			}
			if ca.IsZero() {
				ca = transportCA
				fmt.Println("Extracted remote from transport certificate chain: ", ca)
			}

			// Step 1. create CSR.
			tmpl, err := csrTemplate(chain, flags.templateFile)
			if err != nil {
				return err
			}
			key, err := readECKey(flags.keyFile)
			if err != nil {
				return err
			}
			csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
			if err != nil {
				return err
			}

			// Step 2. create messenger.
			ctx, cancel := context.WithTimeout(context.Background(), flags.timeout)
			defer cancel()
			sds := daemon.NewService(flags.daemon)

			local, err := findLocalAddr(ctx, sds)
			if err != nil {
				return err
			}
			if flags.listen != nil {
				local.Host = &net.UDPAddr{IP: flags.listen}
			}

			remote := &snet.UDPAddr{
				IA: ca,
			}
			disp := reliable.NewDispatcher(flags.dispatcherPath)
			dialer, err := buildDialer(ctx, disp, sds, local, remote)
			if err != nil {
				return err
			}

			// Step 3. renewal scion call.
			signer, err := createSigner(local.IA, trc, chain, flags.transportKeyFile)
			if err != nil {
				return err
			}
			renewed, err := renew(ctx, csr, remote.IA, signer, dialer)
			if err != nil {
				return err
			}

			out := flags.outFile
			if out == "" {
				out = outFileFromSubject(renewed, filepath.Dir(flags.transportCertFile))
			}

			// Step 4. verify with trc.
			if err := cppki.VerifyChain(renewed, cppki.VerifyOptions{TRC: &trc.TRC}); err != nil {
				out += ".unverified"
				fmt.Println("Verification failed, writing chain: ", out)
				if err := writeChain(renewed, out); err != nil {
					fmt.Println("Failed to write unverified chain: ", err)
				}
				return serrors.WrapStr("verification failed", err)
			}

			// Step 5. write to disk.
			if err := writeChain(renewed, out); err != nil {
				return err
			}

			fmt.Printf("Successfully wrote new chain at %s\n", out)
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.templateFile, "template", "",
		"File with data for the CSR in json format")
	cmd.Flags().StringVar(&flags.keyFile, "key", "",
		"Private key file to sign the CSR (required)")
	cmd.MarkFlagRequired("key")
	cmd.Flags().StringVar(&flags.transportCertFile, "transportcert", "",
		"Certificate used to sign the CSR control-plane message (required)")
	cmd.MarkFlagRequired("transportkey")
	cmd.Flags().StringVar(&flags.transportKeyFile, "transportkey", "",
		"Private key file to sign the CSR control-plane message (required)")
	cmd.MarkFlagRequired("transportkey")
	cmd.Flags().StringVar(&flags.trcFilePath, "trc", "", "Trusted TRC (required)")
	cmd.MarkFlagRequired("trc")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 5*time.Second,
		"Timeout for command")
	cmd.Flags().StringVar(&flags.daemon, "sciond", daemon.DefaultAPIAddress,
		"SCION Daemon address")
	cmd.Flags().StringVar(&flags.dispatcherPath, "dispatcher", reliable.DefaultDispPath,
		"Dispatcher socket path")
	cmd.Flags().IPVarP(&flags.listen, "local", "l", nil,
		"Optional local IP address")
	cmd.Flags().StringVar(&flags.outFile, "out", "",
		"File where renewed certificate chain is written")
	cmd.Flags().StringSliceVar(&flags.features, "features", nil,
		fmt.Sprintf("enable development features (%v)", feature.String(&feature.Default{}, "|")))
	return cmd
}

func loadChain(trc cppki.SignedTRC, file string) ([]*x509.Certificate, addr.IA, error) {
	chain, err := cppki.ReadPEMCerts(file)
	if err != nil {
		return nil, addr.IA{}, err
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: &trc.TRC}); err != nil {
		return nil, addr.IA{}, serrors.WrapStr(
			"verification of transport cert failed with provided TRC", err)
	}
	ia, err := cppki.ExtractIA(chain[0].Issuer)
	if err != nil || ia == nil {
		panic("chain is already validated")
	}
	return chain, *ia, nil
}

func createSigner(srcIA addr.IA, trc cppki.SignedTRC, chain []*x509.Certificate,
	keyFile string) (trust.Signer, error) {

	key, err := readECKey(keyFile)
	if err != nil {
		return trust.Signer{}, err
	}
	signer := trust.Signer{
		PrivateKey:   key,
		Algorithm:    signed.ECDSAWithSHA512,
		Hash:         crypto.SHA512,
		IA:           srcIA,
		TRCID:        trc.TRC.ID,
		SubjectKeyID: chain[0].SubjectKeyId,
		Expiration:   time.Now().Add(2 * time.Hour),
		ChainValidity: cppki.Validity{
			NotBefore: chain[0].NotBefore,
			NotAfter:  chain[0].NotAfter,
		},
	}
	return signer, nil
}

func renew(ctx context.Context, csr []byte, dstIA addr.IA, signer trust.Signer,
	dialer grpc.Dialer) ([]*x509.Certificate, error) {

	req, err := renewal.NewChainRenewalRequest(ctx, csr, signer)
	if err != nil {
		return nil, err
	}
	dstSVC := &snet.SVCAddr{
		IA:  dstIA,
		SVC: addr.SvcCS,
	}
	conn, err := dialer.Dial(ctx, dstSVC)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := cppb.NewChainRenewalServiceClient(conn)
	reply, err := client.ChainRenewal(ctx, req, grpc.RetryProfile...)
	if err != nil {
		return nil, err
	}
	// XXX(karampok). We should verify the signature on the payload, but that
	// implies having a full trust engine that is capable of resolving missing
	// certificate chains for the CA. We skip it, since the chain itself is
	// verified against the TRC, and thus, risk is very low.
	body, err := signed.ExtractUnverifiedBody(reply.SignedResponse)
	if err != nil {
		return nil, err
	}
	var replyBody cppb.ChainRenewalResponseBody
	if err := proto.Unmarshal(body, &replyBody); err != nil {
		return nil, err
	}
	chain := make([]*x509.Certificate, 2)
	if chain[0], err = x509.ParseCertificate(replyBody.Chain.AsCert); err != nil {
		return nil, serrors.WrapStr("parsing AS certificate", err)
	}
	if chain[1], err = x509.ParseCertificate(replyBody.Chain.CaCert); err != nil {
		return nil, serrors.WrapStr("parsing CA certificate", err)
	}
	if err := cppki.ValidateChain(chain); err != nil {
		return nil, err
	}
	return chain, nil
}

func csrTemplate(chain []*x509.Certificate, tmpl string) (*x509.CertificateRequest, error) {
	if tmpl == "" {
		s := chain[0].Subject
		s.ExtraNames = s.Names
		return &x509.CertificateRequest{
			Subject:            s,
			SignatureAlgorithm: x509.ECDSAWithSHA512,
		}, nil
	}
	vars, err := readVars(tmpl)
	if err != nil {
		return nil, serrors.WrapStr("reading template", err)
	}
	if vars.ISDAS.IsZero() {
		return nil, serrors.New("isd_as required in template")
	}
	s := pkix.Name{
		CommonName:   vars.CommonName,
		SerialNumber: vars.SerialNumber,
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type:  cppki.OIDNameIA,
				Value: vars.ISDAS.String(),
			},
		},
	}
	for field, value := range map[*[]string]string{
		&s.Country:            vars.Country,
		&s.Organization:       vars.Organization,
		&s.OrganizationalUnit: vars.OrganizationalUnit,
		&s.Locality:           vars.Locality,
		&s.Province:           vars.Province,
		&s.StreetAddress:      vars.StreetAddress,
		&s.PostalCode:         vars.PostalCode,
	} {
		if value != "" {
			*field = []string{value}
		}
	}
	return &x509.CertificateRequest{
		Subject:            s,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}, nil
}

func buildDialer(ctx context.Context, ds reliable.Dispatcher, sds daemon.Service,
	local, remote *snet.UDPAddr) (grpc.Dialer, error) {

	sdConn, err := sds.Connect(ctx)
	if err != nil {
		return nil, serrors.WrapStr("connecting to SCION Daemon", err)
	}

	sn := &snet.SCIONNetwork{
		LocalIA: local.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher: ds,
			SCMPHandler: snet.DefaultSCMPHandler{
				RevocationHandler: daemon.RevHandler{Connector: sdConn},
			},
		},
	}
	conn, err := sn.Dial(ctx, "udp", local.Host, remote, addr.SvcNone)
	if err != nil {
		return nil, serrors.WrapStr("dialing", err)
	}

	dialer := &grpc.QUICDialer{
		Rewriter: &messenger.AddressRewriter{
			Router: &snet.BaseRouter{
				Querier: daemon.Querier{Connector: sdConn, IA: local.IA},
			},
			SVCRouter: svcRouter{Connector: sdConn},
			Resolver: &svc.Resolver{
				LocalIA:     local.IA,
				ConnFactory: sn.Dispatcher,
				LocalIP:     local.Host.IP,
			},
			SVCResolutionFraction: 1,
		},
		Dialer: squic.ConnDialer{
			Conn: conn,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"SCION"},
			},
		},
	}
	return dialer, nil
}

func readECKey(file string) (*ecdsa.PrivateKey, error) {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(raw)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	v, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, serrors.New("only ecdsa keys are supported")
	}
	return v, nil
}

func readVars(file string) (subjectVars, error) {
	c := subjectVars{}
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return subjectVars{}, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return subjectVars{}, err
	}
	return c, nil
}

func writeChain(chain []*x509.Certificate, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	for _, c := range chain {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	return f.Close()
}

func findLocalAddr(ctx context.Context, sds daemon.Service) (*snet.UDPAddr, error) {
	sdConn, err := sds.Connect(ctx)
	if err != nil {
		return nil, err
	}
	localIA, err := sdConn.LocalIA(ctx)
	if err != nil {
		return nil, err
	}
	localIP, err := addrutil.DefaultLocalIP(ctx, sdConn)
	if err != nil {
		return nil, err
	}
	return &snet.UDPAddr{
		IA:   localIA,
		Host: &net.UDPAddr{IP: localIP},
	}, nil
}

func outFileFromSubject(renewed []*x509.Certificate, dir string) string {
	subject, err := cppki.ExtractIA(renewed[0].Subject)
	if err != nil || subject == nil {
		panic("chain is already validated")
	}
	return filepath.Join(dir, fmt.Sprintf("ISD%d-AS%s.%x.pem", subject.I, subject.A.FileFmt(),
		renewed[0].SerialNumber.Bytes()))
}

type svcRouter struct {
	Connector daemon.Connector
}

func (r svcRouter) GetUnderlay(svc addr.HostSVC) (*net.UDPAddr, error) {
	// XXX(karampok). We need to change the interface to not use TODO context.
	return daemon.TopoQuerier{Connector: r.Connector}.UnderlayAnycast(context.TODO(), svc)
}
