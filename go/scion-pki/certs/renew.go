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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
)

type subjectVars struct {
	CommonName         string `json:"common_name,omitempty"`
	Country            string `json:"country,omitempty"`
	ISDAS              string `json:"isd_as,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	PostalCode         string `json:"postal_code,omitempty"`
	Province           string `json:"province,omitempty"`
	SerialNumber       string `json:"serial_number,omitempty"`
	StreetAddress      string `json:"street_address,omitempty"`
}

func newRenewCmd() *cobra.Command {
	var flags struct {
		keyFile           string
		outFile           string
		templateFile      string
		transportCertFile string
		transportKeyFile  string
		trcFilePath       string

		dispatcherPath string
		sciondAddr     string
		listen         net.IP
		timeout        time.Duration
	}

	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew AS certificate",
		Args:  cobra.MinimumNArgs(1),
		Example: strings.Join([]string{
			"scion-pki certs renew",
			"--template vars.json",
			"--key /path/to/cp-as.key",
			"--transportcert /path/to/ISD1-ASff00_0_112.pem",
			"--transportkey /path/tocp-as.key",
			"--trc /path/to/ISD1-B1-S1.trc",
			"--timeout 5s",
			"--out ISD1-ASff00_0_110.new.pem",
			"1-ff00:0:110"}, " \\\n\t"),
		RunE: func(cmd *cobra.Command, args []string) error {
			remoteIA, err := addr.IAFromString(args[0])
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			log.Setup(log.Config{Console: log.ConsoleConfig{Level: "crit"}})

			trc, err := loadTRC(flags.trcFilePath)
			if err != nil {
				return err
			}

			// Step 1. create CSR.
			vars, err := readVars(flags.templateFile)
			if err != nil {
				return err
			}

			key, err := readECKey(flags.keyFile)
			if err != nil {
				return err
			}
			csr, err := buildCSR(vars, key)
			if err != nil {
				return err
			}

			// Step 2. create messenger.
			ctx, cancel := context.WithTimeout(context.Background(), flags.timeout)
			defer cancel()
			sds := sciond.NewService(flags.sciondAddr)

			local, err := findLocalAddr(ctx, sds)
			if err != nil {
				return err
			}
			if flags.listen != nil {
				local.Host = &net.UDPAddr{IP: flags.listen}
			}

			remote := &snet.UDPAddr{
				IA: remoteIA,
			}
			disp := reliable.NewDispatcher(flags.dispatcherPath)
			msgr, err := buildMsgr(ctx, disp, sds, local, remote)
			if err != nil {
				return err
			}

			// Step 3. renewal scion call.
			chain, err := runRenew(ctx, csr, local.IA, remote.IA, trc,
				flags.transportCertFile, flags.transportKeyFile, msgr)
			if err != nil {
				return err
			}

			// Step 4. verify with trc.
			if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: &trc.TRC}); err != nil {
				return serrors.WrapStr("verification failed", err)
			}

			// Step 5. write to disk.
			if err := writeChain(chain, flags.outFile); err != nil {
				return err
			}

			fmt.Printf("Successfully wrote new chain at %s\n", flags.outFile)
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.templateFile, "template", "",
		"File with data for the CSR in json format (required)")
	cmd.MarkFlagRequired("template")
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
	cmd.Flags().StringVar(&flags.sciondAddr, "sciond", sciond.DefaultSCIONDAddress,
		"SCIOND address")
	cmd.Flags().StringVar(&flags.dispatcherPath, "dispatcher", reliable.DefaultDispPath,
		"Dispatcher socket path")
	cmd.Flags().IPVarP(&flags.listen, "local", "l", nil,
		"Optional local IP address")
	cmd.Flags().StringVar(&flags.outFile, "out", "",
		"File where renewed certificate chain is written (required)")
	cmd.MarkFlagRequired("out")

	return cmd
}

func runRenew(ctx context.Context, csr []byte, srcIA, dstIA addr.IA, trc cppki.SignedTRC,
	TransportCertFile, TransportKeyFile string, msgr infra.Messenger) ([]*x509.Certificate, error) {
	chain, err := cppki.ReadPEMCerts(TransportCertFile)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, serrors.New("no transport certificate was found")
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: &trc.TRC}); err != nil {
		return nil, serrors.WrapStr("verification of transport cert failed with provided TRC", err)
	}
	key, err := readECKey(TransportKeyFile)
	if err != nil {
		return nil, err
	}
	req, err := renewal.NewChainRenewalRequest(ctx, csr, trust.Signer{
		PrivateKey:   key,
		Hash:         crypto.SHA512,
		IA:           srcIA,
		TRCID:        trc.TRC.ID,
		SubjectKeyID: chain[0].SubjectKeyId,
		Expiration:   time.Now().Add(2 * time.Hour),
		ChainValidity: cppki.Validity{
			NotBefore: chain[0].NotBefore,
			NotAfter:  chain[0].NotAfter,
		},
	})
	if err != nil {
		return nil, err
	}
	dstSVC := &snet.SVCAddr{
		IA:  dstIA,
		SVC: addr.SvcCS,
	}
	rep, err := msgr.RequestChainRenewal(ctx, req, dstSVC, messenger.NextId())
	if err != nil {
		return nil, err
	}
	// XXX(karampok). We should verify the signature on the payload, but that
	// implies having a full trust engine that is capable of resolving missing
	// certificate chains for the CA. We skip it, since the chain itself is
	// verified against the TRC, and thus, risk is very low.
	return rep.Chain()
}

func buildCSR(c subjectVars, key *ecdsa.PrivateKey) ([]byte, error) {
	s := pkix.Name{
		CommonName:         c.CommonName,
		Country:            []string{c.Country},
		Organization:       []string{c.Organization},
		OrganizationalUnit: []string{c.OrganizationalUnit},
		Locality:           []string{c.Locality},
		Province:           []string{c.Province},
		StreetAddress:      []string{c.StreetAddress},
		PostalCode:         []string{c.PostalCode},
		SerialNumber:       c.SerialNumber,
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type:  cppki.OIDNameIA,
				Value: c.ISDAS,
			},
		},
	}
	csrTemplate := x509.CertificateRequest{
		Subject:            s,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	return x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
}

func buildMsgr(ctx context.Context, ds reliable.Dispatcher, sds sciond.Service,
	local, remote *snet.UDPAddr) (infra.Messenger, error) {
	sdConn, err := sds.Connect(ctx)
	if err != nil {
		return nil, serrors.WrapStr("connecting to SCION Daemon", err)
	}
	sn := snet.NewNetwork(local.IA, ds, sciond.RevHandler{Connector: sdConn})
	conn, err := sn.Dial(ctx, "udp", local.Host, remote, addr.SvcNone)
	if err != nil {
		return nil, serrors.WrapStr("dialing", err)
	}
	return messenger.New(
		&messenger.Config{
			IA:         local.IA,
			Dispatcher: disp.New(conn, messenger.DefaultAdapter, log.New()),
			AddressRewriter: &messenger.AddressRewriter{
				Router: &snet.BaseRouter{
					Querier: sciond.Querier{Connector: sdConn, IA: local.IA},
				},
				SVCRouter: svcRouter{Connector: sdConn},
				Resolver: &svc.Resolver{
					LocalIA: local.IA,
					ConnFactory: &snet.DefaultPacketDispatcherService{
						Dispatcher: ds,
					},
					LocalIP: local.Host.IP,
					Payload: []byte{0x00, 0x00, 0x00, 0x00},
				},
				SVCResolutionFraction: 1,
			},
			QUIC: &messenger.QUICConfig{
				Conn: conn,
				TLSConfig: &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"SCION"},
				},
			},
		},
	), nil
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

func findLocalAddr(ctx context.Context, sds sciond.Service) (*snet.UDPAddr, error) {
	sdConn, err := sds.Connect(ctx)
	if err != nil {
		return nil, err
	}
	localIA, err := sdConn.LocalIA(ctx)
	if err != nil {
		return nil, err
	}
	csAddr, err := sciond.TopoQuerier{Connector: sdConn}.UnderlayAnycast(ctx, addr.SvcCS)
	if err != nil {
		return nil, err
	}
	localIP, err := addrutil.ResolveLocal(csAddr.IP)
	if err != nil {
		return nil, err
	}
	return &snet.UDPAddr{
		IA:   localIA,
		Host: &net.UDPAddr{IP: localIP},
	}, nil
}

type svcRouter struct {
	Connector sciond.Connector
}

func (r svcRouter) GetUnderlay(svc addr.HostSVC) (*net.UDPAddr, error) {
	// XXX(karampok). We need to change the interface to not use TODO context.
	return sciond.TopoQuerier{Connector: r.Connector}.UnderlayAnycast(context.TODO(), svc)
}
