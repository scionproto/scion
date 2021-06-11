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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/app/feature"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/scion-pki/file"
	"github.com/scionproto/scion/go/scion-pki/key"
)

const (
	subjectHelp = `
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
`
)

type SubjectVars struct {
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

type Features struct {
}

func newRenewCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		out        string
		outKey     string
		outCSR     string
		outCMS     string
		subject    string
		commonName string
		trcFiles   []string
		reuseKey   bool
		ca         string
		curve      string
		expiresIn  string

		dispatcherPath string
		daemon         string
		listen         net.IP
		timeout        time.Duration
		tracer         string
		logLevel       string

		force    bool
		backup   bool
		features []string
	}
	cmd := &cobra.Command{
		Use:   "renew [flags] <chain-file> <key-file>",
		Short: "Renew an AS certificate",
		Example: fmt.Sprintf(`  %[1]s renew --trc ISD1-B1-S1.trc --backup cp-as.pem cp-as.key
  %[1]s renew --trc ISD1-B1-S1.trc,ISD1-B1-S2.trc --force cp-as.pem cp-as.key
  %[1]s renew --trc ISD1-B1-S1.trc --reuse-key --out cp-as.new.pem cp-as.pem cp-as.key
  %[1]s renew --trc ISD1-B1-S1.trc --backup --expires-in 56h cp-as.pem cp-as.key
  %[1]s renew --trc ISD1-B1-S1.trc --backup --expires-in 0.75 cp-as.pem cp-as.key
`, pather.CommandPath()),
		Long: `'renew' requests a renewed AS certificate from a remote CA control service.

The provided <chain-file> and <key-file> are used to sign the CSR. They must be
valid and verifiable by the CA in order for the request to be served.

The renewed certificate chain is requested with a fresh private key, unless the
--reuse-key flag is set.

The TRCs are used to validate and verify the renewed certificate chain. If the
chain is not verifiable with any of the active TRCs, the certificate chain and,
if applicable, the fresh private key are written to the provided file paths with
the '.unverified' suffix.

The resulting certificate chain is written to the file system, either to
<chain-file> or to --out, if specified.

The fresh private key is is written to the file stystem, either to <key-file>
or to --out-key, if specified.

Files are not allowed to be overwritten, by default. Either you have to specify
the --out and --out-key flags explicitly, or specify the --force or --backup
flags. In case the --backup flag is set, every file that would be overwritten is
renamed to contain a local execution time timestamp before the file extension.
E.g., <filename-base>.<YYYY-MM-DD-HH-MM-SS>.<filename-ext>.

This command supports the --expires-in flag in order for it to be run in a
periodic task runner (e.g., cronjob). The flag indicates the acceptable remaining
time before certificate expiration. If the remaining time is larger or equal to
the specified value, the command immediately exits with code zero. If the
remaining time is less than the specified value, a renewal run is executed.
The time can either be specified as a time duration or a relative factor of the
existing certificate chain. For the time duration, the following units are
supported: d, h, m, s. The relative factor is supplied as a floating point
number. For example, a factor of 0.75 indicates that the certificate chain
should be renewed after one quarter of its lifetime has passed, and it still
has three quarters of its validity period until it expires.

Unless a subject template is specified, the subject of the existing certificate
chain is used as the subject for the renewal request.

The template is expressed in JSON. A valid example:
` + subjectHelp,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			certFile := args[0]
			keyFile := args[1]

			expiryChecker, err := parseExpiresIn(flags.expiresIn)
			if err != nil {
				return serrors.WrapStr("parsing --expires-in", err)
			}

			cmd.SilenceUsage = true

			if !flags.backup && !flags.force {
				certSet, keySet := flags.out != "", flags.outKey != ""
				switch {
				case certSet && keySet:
				case certSet && flags.reuseKey:
				case certSet:
					return serrors.New("not allowed to overwrite private key")
				default:
					return serrors.New("not allowed to overwrite certificate")
				}

			}

			var ca addr.IA
			if flags.ca != "" {
				var err error
				if ca, err = addr.IAFromString(flags.ca); err != nil {
					return serrors.WrapStr("parsing CA", err)
				}
			}

			opts := []file.Option{file.WithForce(flags.force)}
			if flags.backup {
				opts = append(opts,
					file.WithBackup(time.Now().Local().Format("2006-01-02-15-04-05")),
				)
			}

			// Set up observability tooling.
			if err := app.SetupLog(flags.logLevel); err != nil {
				return err
			}
			closer, err := setupTracer("scion-pki", flags.tracer)
			if err != nil {
				return serrors.WrapStr("setting up tracing", err)
			}
			defer closer()

			var features Features
			if err := feature.Parse(flags.features, &features); err != nil {
				return err
			}
			span, ctx := tracing.CtxWith(context.Background(), "certs.renew")
			defer span.Finish()

			trcs, err := loadTRCs(flags.trcFiles)
			if err != nil {
				return err
			}
			chain, issuer, err := loadChain(trcs, certFile)
			if err != nil {
				return err
			}

			if nb, na := chain[0].NotBefore, chain[0].NotAfter; !expiryChecker.ShouldRenew(nb, na) {
				fmt.Println("Skipping renewal, --expires-in threshold is not reached.")
				fmt.Println("AS certificate validity:")
				fmt.Println("    NotBefore: ", nb)
				fmt.Println("    NotAfter:  ", na)
				return nil
			}

			if ca.IsZero() {
				fmt.Println("Extracted issuer from certificate chain: ", issuer)
				ca = issuer
			}
			span.SetTag("dst.isd_as", ca)

			// Load private key.
			privPrev, err := key.LoadPrivateKey(keyFile)
			if err != nil {
				return serrors.WrapStr("reading private key", err)
			}
			privNext := key.PrivateKey(privPrev)

			// Create fresh private key, unless requested otherwise. Encode it
			// to PEM here to catch problems early on.
			var pemPrivNext []byte
			if !flags.reuseKey {
				if privNext, err = key.GeneratePrivateKey(flags.curve); err != nil {
					return serrors.WrapStr("creating fresh private key", err)
				}
				if pemPrivNext, err = key.EncodePEMPrivateKey(privNext); err != nil {
					return serrors.WrapStr("encoding fresh private key", err)
				}
			}

			template := certFile
			if flags.subject != "" {
				template = flags.subject
			}
			subject, err := createSubject(template, flags.commonName)
			if err != nil {
				return err
			}

			csr, err := CreateCSR(cppki.AS, subject, privNext)
			if err != nil {
				return serrors.WrapStr("creating CSR", err)
			}
			if flags.outCSR != "" {
				pemCSR := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csr,
				})
				err = file.WriteFile(flags.outCSR, pemCSR, 0666, opts...)
				if err != nil {
					// The CSR is not important, carry on with execution.
					fmt.Fprintln(os.Stderr, "Failed to write CSR:", err.Error())
				}
			}

			// Create messenger.
			ctx, cancel := context.WithTimeout(ctx, flags.timeout)
			defer cancel()
			sds := daemon.NewService(flags.daemon)
			local, err := findLocalAddr(ctx, sds)
			if err != nil {
				return err
			}
			if flags.listen != nil {
				local.Host = &net.UDPAddr{IP: flags.listen}
			}
			remote := &snet.UDPAddr{IA: ca}
			disp := reliable.NewDispatcher(flags.dispatcherPath)
			dialer, err := buildDialer(ctx, disp, sds, local, remote)
			if err != nil {
				return err
			}

			// Sign the request.
			algo, err := signed.SelectSignatureAlgorithm(privPrev.Public())
			if err != nil {
				return err
			}
			signer := trust.Signer{
				PrivateKey:   privPrev,
				Algorithm:    algo,
				IA:           local.IA,
				TRCID:        trcs[0].ID,
				SubjectKeyID: chain[0].SubjectKeyId,
				Expiration:   time.Now().Add(2 * time.Hour),
				ChainValidity: cppki.Validity{
					NotBefore: chain[0].NotBefore,
					NotAfter:  chain[0].NotAfter,
				},
				Subject: chain[0].Subject,
				Chain:   chain,
			}
			var req cppb.ChainRenewalRequest
			cmsReq, err := renewal.NewChainRenewalRequest(ctx, csr, signer)
			if err != nil {
				return err
			}
			req.CmsSignedRequest = cmsReq.CmsSignedRequest
			if flags.outCMS != "" {
				if req.CmsSignedRequest == nil {
					return serrors.New("cannot write request to file: no request created")
				}
				pemReq := pem.EncodeToMemory(&pem.Block{
					Type:  "CMS",
					Bytes: req.CmsSignedRequest,
				})
				err = file.WriteFile(flags.outCMS, pemReq, 0666, opts...)
				if err != nil {
					// The CMS request is not important, carry on with execution.
					fmt.Fprintln(os.Stderr, "Failed to write CMS request:", err.Error())
				}
			}

			// Send the request via SCION and extract the chain.
			rep, err := sendRequest(ctx, remote.IA, dialer, &req)
			if err != nil {
				return err
			}
			renewed, err := extractChain(rep)
			if err != nil {
				return err
			}
			pemRenewed, err := encodeChain(renewed)
			if err != nil {
				return err
			}

			outCertFile, outKeyFile := certFile, keyFile
			if flags.out != "" {
				outCertFile = flags.out
			}
			if flags.outKey != "" {
				outKeyFile = flags.outKey
			}

			// Verify certificate chain
			verifyOptions := cppki.VerifyOptions{TRC: trcs}
			if verifyError := cppki.VerifyChain(renewed, verifyOptions); verifyError != nil {
				outCertFile += ".unverified"
				fmt.Printf("Writing unverified chain: %q\n", outCertFile)
				if err := file.WriteFile(outCertFile, pemRenewed, 0644, opts...); err != nil {
					fmt.Println("Failed to write unverified chain: ", err)
				}
				if pemPrivNext != nil {
					outKeyFile += ".unverified"
					fmt.Printf("Writing private key for unverified chain: %q\n", outKeyFile)
					if err := file.WriteFile(outKeyFile, pemPrivNext, 0600, opts...); err != nil {
						fmt.Println("Failed to write private key for unverified chain: ", err)
					}
				}
				if maybeMissingTRCInGrace(trcs) {
					fmt.Println("Verification failed, but current time still in Grace Period " +
						"of latest TRC")
					fmt.Printf("Try to verify with the predecessor TRC: (Base = %d, Serial = %d)\n",
						trcs[0].ID.Base, trcs[0].ID.Serial-1)
				}
				return serrors.WrapStr("verification failed", verifyError)
			}

			if pemPrivNext != nil {
				if err := file.WriteFile(outKeyFile, pemPrivNext, 0600, opts...); err != nil {
					return serrors.WrapStr("writing fresh private key", err)
				}
				fmt.Printf("Private key successfully written to %q\n", outKeyFile)
			}

			if err := file.WriteFile(outCertFile, pemRenewed, 0644, opts...); err != nil {
				return serrors.WrapStr("writing renewed certificate chain", err)
			}
			fmt.Printf("Certificate chain successfully written to %q\n", outCertFile)
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.out, "out", "",
		"The path to write the renewed certificate chain",
	)
	cmd.Flags().StringVar(&flags.outKey, "out-key", "",
		"The path to write the fresh private key",
	)
	cmd.Flags().StringVar(&flags.outCSR, "out-csr", "",
		"The path to write the CSR sent to the CA",
	)
	cmd.Flags().StringVar(&flags.outCMS, "out-cms", "",
		"The path to write the CMS signed CSR sent to the CA",
	)
	cmd.Flags().StringVar(&flags.subject, "subject", "",
		"The path to the custom subject for the CSR",
	)
	cmd.Flags().StringVar(&flags.commonName, "common-name", "",
		"The common name that replaces the common name in the subject template",
	)
	cmd.Flags().StringSliceVar(&flags.trcFiles, "trc", []string{},
		"Comma-separated list of trusted TRC files. If more than two TRCs are specified,\n"+
			"only up to two active TRCs with the highest Base version are used (required)")

	cmd.Flags().BoolVar(&flags.reuseKey, "reuse-key", false,
		"Reuse the provided private key instead of creating a fresh private key",
	)
	cmd.Flags().StringVar(&flags.ca, "ca", "",
		"The ISD-AS of the CA to request the renewed certificate chain",
	)
	cmd.Flags().StringVar(&flags.curve, "curve", "P-256",
		"The elliptic curve to use (P-256|P-384|P-521)",
	)
	cmd.Flags().StringVar(&flags.expiresIn, "expires-in", "",
		"Remaining time threshold for renewal",
	)
	cmd.Flags().BoolVar(&flags.force, "force", false,
		"Force overwritting existing files",
	)
	cmd.Flags().BoolVar(&flags.backup, "backup", false,
		"Back up existing files before overwriting",
	)
	cmd.Flags().StringVar(&flags.dispatcherPath, "dispatcher", reliable.DefaultDispPath,
		"The path to the dispatcher socket",
	)
	cmd.Flags().StringVar(&flags.daemon, "sciond", daemon.DefaultAPIAddress,
		"The SCION Daemon address",
	)
	cmd.Flags().IPVar(&flags.listen, "local", nil,
		"The local IP address to use",
	)
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 10*time.Second,
		"The timeout for the renewal request",
	)
	cmd.Flags().StringSliceVar(&flags.features, "features", nil,
		fmt.Sprintf("enable development features (%v)", feature.String(&Features{}, "|")),
	)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "",
		"The tracing agent address",
	)
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)

	cmd.MarkFlagRequired("trc")

	return cmd
}

func encodeChain(chain []*x509.Certificate) ([]byte, error) {
	var buffer bytes.Buffer
	for _, c := range chain {
		if err := pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

type expiryChecker struct {
	duration time.Duration
	factor   float64
}

func parseExpiresIn(flag string) (expiryChecker, error) {
	if flag == "" {
		return expiryChecker{}, nil
	}
	if dur, err := util.ParseDuration(flag); err == nil {
		if dur < 0 {
			return expiryChecker{}, serrors.New("negative duration not allowed")
		}
		return expiryChecker{duration: dur}, nil
	}
	if dur, err := time.ParseDuration(flag); err == nil {
		if dur < 0 {
			return expiryChecker{}, serrors.New("negative duration not allowed")
		}
		return expiryChecker{duration: dur}, nil
	}
	if factor, err := strconv.ParseFloat(flag, 64); err == nil {
		if factor < 0 {
			return expiryChecker{}, serrors.New("negative factor not allowed")
		}
		return expiryChecker{factor: factor}, nil
	}
	return expiryChecker{}, serrors.New("failed to parse input")
}

func (c expiryChecker) ShouldRenew(notBefore, notAfter time.Time) bool {
	if c == (expiryChecker{}) {
		return true
	}
	leadTime := c.duration
	if c.duration == 0 {
		diff := notAfter.Sub(notBefore)
		leadTime = time.Duration(diff.Seconds()*c.factor) * time.Second
	}
	return time.Until(notAfter) < leadTime
}

func loadChain(trcs []*cppki.TRC, file string) ([]*x509.Certificate, addr.IA, error) {
	chain, err := cppki.ReadPEMCerts(file)
	if err != nil {
		return nil, addr.IA{}, err
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: trcs}); err != nil {
		if maybeMissingTRCInGrace(trcs) {
			fmt.Println("Verification failed, but current time still in Grace Period of latest TRC")
			fmt.Printf("Try to verify with the predecessor TRC: (Base = %d, Serial = %d)\n",
				trcs[0].ID.Base, trcs[0].ID.Serial-1)
		}
		return nil, addr.IA{}, serrors.WrapStr(
			"verification of transport cert failed with provided TRC", err)
	}
	ia, err := cppki.ExtractIA(chain[0].Issuer)
	if err != nil {
		panic("chain is already validated")
	}
	return chain, ia, nil
}

func sendRequest(
	ctx context.Context,
	dstIA addr.IA,
	dialer grpc.Dialer,
	req *cppb.ChainRenewalRequest,
) (*cppb.ChainRenewalResponse, error) {

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
	return reply, err
}

func extractChain(rep *cppb.ChainRenewalResponse) ([]*x509.Certificate, error) {
	// XXX(karampok). We should verify the signature on the payload, but that
	// implies having a full trust engine that is capable of resolving missing
	// certificate chains for the CA. We skip it, since the chain itself is
	// verified against the TRC, and thus, risk is very low.
	if len(rep.CmsSignedResponse) == 0 {
		return extractChainLegacy(rep)
	}
	ci, err := protocol.ParseContentInfo(rep.CmsSignedResponse)
	if err != nil {
		return nil, err
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		return nil, err
	}
	raw, err := sd.EncapContentInfo.DataEContent()
	if err != nil {
		return nil, err
	}
	chain, err := x509.ParseCertificates(raw)
	if err != nil {
		return nil, err
	}
	if err := cppki.ValidateChain(chain); err != nil {
		return nil, err
	}
	return chain, nil
}

func extractChainLegacy(rep *cppb.ChainRenewalResponse) ([]*x509.Certificate, error) {
	body, err := signed.ExtractUnverifiedBody(rep.SignedResponse)
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

func subjectFromVars(vars SubjectVars) (pkix.Name, error) {
	if vars.ISDAS.IsZero() {
		return pkix.Name{}, serrors.New("isd_as required in template")
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
	return s, nil
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

type svcRouter struct {
	Connector daemon.Connector
}

func (r svcRouter) GetUnderlay(svc addr.HostSVC) (*net.UDPAddr, error) {
	// XXX(karampok). We need to change the interface to not use TODO context.
	return daemon.TopoQuerier{Connector: r.Connector}.UnderlayAnycast(context.TODO(), svc)
}

func maybeMissingTRCInGrace(trcs []*cppki.TRC) bool {
	return len(trcs) == 1 && trcs[0].InGracePeriod(time.Now())
}
