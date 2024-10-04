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
	"io"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/resolver"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app"
	infraenv "github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/app/feature"
	"github.com/scionproto/scion/private/app/flag"
	"github.com/scionproto/scion/private/app/path"
	"github.com/scionproto/scion/private/ca/renewal"
	"github.com/scionproto/scion/private/svc"
	"github.com/scionproto/scion/private/tracing"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/scion-pki/file"
	"github.com/scionproto/scion/scion-pki/key"
)

const (
	subjectHelp = `
  {
    "common_name": "1-ff00:0:110 AS certificate",
    "country": "CH",
    "isd_as": "1-ff00:0:110"
  }

All configurable fields with their type are defined by the following JSON
schema::

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

For more information on JSON schemas, see https://json-schema.org/.
`
)

type SubjectVars struct {
	IA                 addr.IA `json:"isd_as,omitempty"`
	CommonName         string  `json:"common_name,omitempty"`
	Country            string  `json:"country,omitempty"`
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
	var envFlags flag.SCIONEnvironment
	var flags struct {
		out        string
		outKey     string
		outCSR     string
		outCMS     string
		subject    string
		commonName string
		trcFiles   []string
		reuseKey   bool
		ca         []string
		remotes    []string
		curve      string
		expiresIn  string

		timeout  time.Duration
		tracer   string
		logLevel string

		force    bool
		backup   bool
		features []string

		interactive bool
		noColor     bool
		refresh     bool
		noProbe     bool
		sequence    string
	}
	cmd := &cobra.Command{
		Use:   "renew [flags] <chain-file> <key-file>",
		Short: "Renew an AS certificate",
		Example: fmt.Sprintf(`  %[1]s renew --trc ISD1-B1-S1.trc --backup cp-as.pem cp-as.key
  %[1]s renew --trc ISD1-B1-S1.trc,ISD1-B1-S2.trc --force cp-as.pem cp-as.key
  %[1]s renew --trc ISD1-B1-S1.trc --reuse-key --out cp-as.new.pem cp-as.pem cp-as.key
  %[1]s renew --trc ISD1-B1-S1.trc --backup --expires-in 56h cp-as.pem cp-as.key
  %[1]s renew --trc ISD1-B1-S1.trc --backup --expires-in 0.75 cp-as.pem cp-as.key
  %[1]s renew --trc ISD1-B1-S1.trc --backup --ca 1-ff00:0:110,1-ff00:0:120 cp-as.pem cp-as.key
  %[1]s renew --trc ISD1-B1-S1.trc --backup \
  	--remote 1-ff00:0:110,10.0.0.3 --remote 1-ff00:0:120,172.30.200.2 cp-as.pem cp-as.key
`, pather.CommandPath()),
		Long: `'renew' requests a renewed AS certificate from a remote CA control service.

The provided <chain-file> and <key-file> are used to sign the CSR. They must be
valid and verifiable by the CA in order for the request to be served.

The renewed certificate chain is requested with a fresh private key, unless the
\--reuse-key flag is set.

By default, the target CA for the request is extracted from the certificate
chain that is renewed. To select a different CA, you can specify the \--ca flag
with one or multiple target CAs. If multiple CAs are specified, they are tried
in the order that they are declared until the first successful certificate
chain renewal. If none of the declared CAs issued a verifiable certificate chain,
the command returns a non-zero exit code.

The TRCs are used to validate and verify the renewed certificate chain. If the
chain is not verifiable with any of the active TRCs, the certificate chain and,
if applicable, the fresh private key are written to the provided file paths with
the '<CA>.unverified' suffix, where CA is the ISD-AS number of the CA AS that
issued the unverifiable certificate chain.

The resulting certificate chain is written to the file system, either to
<chain-file> or to \--out, if specified.

The fresh private key is is written to the file stystem, either to <key-file>
or to \--out-key, if specified.

Files are not allowed to be overwritten, by default. Either you have to specify
the \--out and \--out-key flags explicitly, or specify the \--force or \--backup
flags. In case the \--backup flag is set, every file that would be overwritten is
renamed to contain a local execution time timestamp before the file extension.
E.g., <filename-base>.<YYYY-MM-DD-HH-MM-SS>.<filename-ext>.

This command supports the \--expires-in flag in order for it to be run in a
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

The template is expressed in JSON. A valid example::
` + subjectHelp,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			certFile := args[0]
			keyFile := args[1]
			printErr := func(f string, ctx ...interface{}) {
				fmt.Fprintf(cmd.ErrOrStderr(), f, ctx...)
			}
			printf := func(f string, ctx ...interface{}) {
				fmt.Fprintf(cmd.OutOrStdout(), f, ctx...)
			}

			expiryChecker, err := parseExpiresIn(flags.expiresIn)
			if err != nil {
				return serrors.Wrap("parsing --expires-in", err)
			}

			if len(flags.ca) > 0 && len(flags.remotes) > 0 {
				return serrors.New("--ca and --remote must not both be set")
			}

			cmd.SilenceUsage = true

			var features Features
			if err := feature.Parse(flags.features, &features); err != nil {
				return err
			}

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
				return serrors.Wrap("setting up tracing", err)
			}
			defer closer()

			span, ctx := tracing.CtxWith(cmd.Context(), "certificate.renew")
			defer span.Finish()

			if err := envFlags.LoadExternalVars(); err != nil {
				return err
			}
			daemonAddr := envFlags.Daemon()
			localIP := net.IP(envFlags.Local().AsSlice())
			log.Debug("Resolved SCION environment flags",
				"daemon", daemonAddr,
				"local", localIP,
			)

			// Setup basic state.
			daemonCtx, daemonCancel := context.WithTimeout(ctx, time.Second)
			defer daemonCancel()
			sd, err := daemon.NewService(daemonAddr).Connect(daemonCtx)
			if err != nil {
				return serrors.Wrap("connecting to SCION Daemon", err)
			}
			defer sd.Close()

			info, err := app.QueryASInfo(daemonCtx, sd)
			if err != nil {
				return err
			}
			span.SetTag("src.isd_as", info.IA)

			// Load cryptographic material
			trcs, err := loadTRCs(flags.trcFiles)
			if err != nil {
				return err
			}
			chain, err := loadChain(trcs, certFile)
			if err != nil {
				return err
			}

			if nb, na := chain[0].NotBefore, chain[0].NotAfter; !expiryChecker.ShouldRenew(nb, na) {
				printf("Skipping renewal, --expires-in threshold is not reached.\n")
				printf("AS certificate validity:\n")
				printf("    NotBefore: %s\n", nb)
				printf("    NotAfter:  %s\n", na)
				return nil
			}

			var cas []addr.IA
			var remotes []*snet.UDPAddr
			switch {
			case len(flags.ca) > 0:
				for _, raw := range flags.ca {
					ca, err := addr.ParseIA(raw)
					if err != nil {
						return serrors.Wrap("parsing CA", err)
					}
					cas = append(cas, ca)
				}
			case len(flags.remotes) > 0:
				for _, raw := range flags.remotes {
					addr, err := snet.ParseUDPAddr(raw)
					if err != nil {
						return serrors.Wrap("parsing remote", err)
					}
					remotes = append(remotes, addr)
				}
			default:
				ia, err := cppki.ExtractIA(chain[0].Issuer)
				if err != nil {
					panic(fmt.Sprintf("extracting ISD-AS from verified chain: %s", err))
				}
				printf("Extracted issuer from certificate chain: %s\n", ia)
				cas = []addr.IA{ia}
			}
			span.SetTag("ca-options", cas)
			span.SetTag("remote-options", remotes)

			// Load private key.
			// XXX(roosd): The renewal process does currently not support KMS.
			// This is a bit more involved, and requires some refactoring of the
			// flags and the key loading/creation process. For now, KMS is also
			// not a direct use-case for AS certificates.
			privPrev, err := key.LoadPrivateKey("", keyFile)
			if err != nil {
				return serrors.Wrap("reading private key", err)
			}
			privNext := key.PrivateKey(privPrev)

			// Create fresh private key, unless requested otherwise. Encode it
			// to PEM here to catch problems early on.
			var pemPrivNext []byte
			if !flags.reuseKey {
				if privNext, err = key.GeneratePrivateKey(flags.curve); err != nil {
					return serrors.Wrap("creating fresh private key", err)
				}
				if pemPrivNext, err = key.EncodePEMPrivateKey(privNext); err != nil {
					return serrors.Wrap("encoding fresh private key", err)
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
				return serrors.Wrap("creating CSR", err)
			}
			if flags.outCSR != "" {
				pemCSR := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csr,
				})
				err = file.WriteFile(flags.outCSR, pemCSR, 0666, opts...)
				if err != nil {
					// The CSR is not important, carry on with execution.
					printErr("Failed to write CSR: %s\n", err.Error())
				}
			}

			// Sign the request.
			algo, err := signed.SelectSignatureAlgorithm(privPrev.Public())
			if err != nil {
				return err
			}
			signer := trust.Signer{
				PrivateKey:   privPrev,
				Algorithm:    algo,
				IA:           info.IA,
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
					printErr("Failed to write CMS request: %s\n", err.Error())
				}
			}

			r := renewer{
				LocalIA: info.IA,
				LocalIP: localIP,
				Daemon:  sd,
				Timeout: flags.timeout,
				StdErr:  cmd.ErrOrStderr(),
				PathOptions: func() []path.Option {
					pathOpts := []path.Option{
						path.WithInteractive(flags.interactive),
						path.WithRefresh(flags.refresh),
						path.WithSequence(flags.sequence),
						path.WithColorScheme(path.DefaultColorScheme(flags.noColor)),
					}
					if !flags.noProbe {
						pathOpts = append(pathOpts, path.WithProbing(&path.ProbeConfig{
							LocalIA: info.IA,
							LocalIP: localIP,
						}))
					}
					return pathOpts
				},
			}

			outCertFile, outKeyFile := certFile, keyFile
			if flags.out != "" {
				outCertFile = flags.out
			}
			if flags.outKey != "" {
				outKeyFile = flags.outKey
			}

			request := func(ca addr.IA, remote net.Addr) ([]*x509.Certificate, error) {
				printf("Attempt certificate renewal with %s\n", ca)

				span, ctx := tracing.CtxWith(ctx, "request")
				span.SetTag("dst.isd_as", ca)

				chain, err := r.Request(ctx, &req, remote, ca)
				if err != nil {
					printErr("Sending request failed: %s\n", err)
					return nil, err
				}

				// Verify certificate chain
				verifyOptions := cppki.VerifyOptions{TRC: trcs}
				if verifyError := cppki.VerifyChain(chain, verifyOptions); verifyError != nil {
					suffix := "." + addr.FormatIA(ca, addr.WithFileSeparator()) + ".unverified"

					printErr("Verification failed: %s\n", verifyError)

					// Write chain.
					certFile := outCertFile + suffix
					printErr("Writing unverified chain: %q\n", certFile)
					pem := encodeChain(chain)
					if err := file.WriteFile(certFile, pem, 0644, opts...); err != nil {
						fmt.Println("Failed to write unverified chain: ", err)
					}

					// Write private key
					if pemPrivNext != nil {
						keyFile := outKeyFile + suffix
						printErr("Writing private key for unverified chain: %q\n", keyFile)
						if err := file.WriteFile(keyFile, pemPrivNext, 0600, opts...); err != nil {
							fmt.Println("Failed to write private key for unverified chain: ", err)
						}
					}

					// Output helpful info in case the TRC is in grace period.
					if maybeMissingTRCInGrace(trcs) {
						printErr(
							"Current time is still in Grace Period of latest TRC.\n"+
								"Try to verify with the predecessor TRC: "+
								"(Base = %d, Serial = %d)\n",
							trcs[0].ID.Base, trcs[0].ID.Serial-1,
						)
					}
					return nil, serrors.Wrap("verification failed", verifyError)
				}
				return chain, nil
			}

			var renewed []*x509.Certificate
			switch {
			case len(cas) > 0:
				for _, ca := range cas {
					remote := &snet.SVCAddr{SVC: addr.SvcCS}
					chain, err := request(ca, remote)
					if err != nil {
						continue
					}
					renewed = chain
					break
				}
			case len(remotes) > 0:
				for _, remote := range remotes {
					chain, err := request(remote.IA, remote)
					if err != nil {
						continue
					}
					renewed = chain
					break
				}
			}
			if renewed == nil {
				return serrors.New("failed to request certificate chain")
			}
			pemRenewed := encodeChain(renewed)

			if pemPrivNext != nil {
				if err := file.WriteFile(outKeyFile, pemPrivNext, 0600, opts...); err != nil {
					return serrors.Wrap("writing fresh private key", err)
				}
				printf("Private key successfully written to %q\n", outKeyFile)
			}
			if err := file.WriteFile(outCertFile, pemRenewed, 0644, opts...); err != nil {
				return serrors.Wrap("writing renewed certificate chain", err)
			}
			printf("Certificate chain successfully written to %q\n", outCertFile)
			return nil
		},
	}

	envFlags.Register(cmd.Flags())
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
		"Comma-separated list of trusted TRC files or glob patterns. "+
			"If more than two TRCs are specified,\n only up to two active TRCs "+
			"with the highest Base version are used (required)",
	)
	cmd.Flags().BoolVar(&flags.reuseKey, "reuse-key", false,
		"Reuse the provided private key instead of creating a fresh private key",
	)
	cmd.Flags().StringSliceVar(&flags.ca, "ca", nil,
		"Comma-separated list of ISD-AS identifiers of target CAs.\n"+
			"The CAs are tried in order until success or all of them failed.\n"+
			"--ca is mutually exclusive with --remote",
	)
	cmd.Flags().StringArrayVar(&flags.remotes, "remote", nil,
		"The remote CA address to use for certificate renewal.\n"+
			"The address is of the form <ISD-AS>,<IP>. --remote can be specified multiple times\n"+
			"and all specified remotes are tried in order until success or all of them failed.\n"+
			"--remote is mutually exclusive with --ca.",
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
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 10*time.Second,
		"The timeout for the renewal request per CA",
	)
	cmd.Flags().StringSliceVar(&flags.features, "features", nil,
		fmt.Sprintf("enable development features (%v)", feature.String(&Features{}, "|")),
	)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "",
		"The tracing agent address",
	)
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)

	cmd.Flags().BoolVarP(&flags.interactive, "interactive", "i", false, "interactive mode")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().StringVar(&flags.sequence, "sequence", "", app.SequenceUsage)
	cmd.Flags().BoolVar(&flags.noProbe, "no-probe", false, "do not probe paths for health")
	cmd.Flags().BoolVar(&flags.refresh, "refresh", false, "set refresh flag for path request")

	cmd.MarkFlagRequired("trc")

	return cmd
}

type renewer struct {
	LocalIA     addr.IA
	LocalIP     net.IP
	PathOptions func() []path.Option
	Daemon      daemon.Connector
	Disatcher   string
	Timeout     time.Duration
	StdErr      io.Writer
}

func (r *renewer) Request(
	ctx context.Context,
	req *cppb.ChainRenewalRequest,
	remote net.Addr,
	ca addr.IA,
) ([]*x509.Certificate, error) {

	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	if ca == r.LocalIA {
		return r.requestLocal(ctx, req, remote)
	}
	return r.requestRemote(ctx, req, remote, ca)
}

func (r *renewer) requestLocal(
	ctx context.Context,
	req *cppb.ChainRenewalRequest,
	remote net.Addr,
) ([]*x509.Certificate, error) {

	dialer := &grpc.TCPDialer{
		SvcResolver: func(hs addr.SVC) []resolver.Address {
			// Do the SVC resolution
			entries, err := r.Daemon.SVCInfo(ctx, []addr.SVC{hs})
			if err != nil {
				fmt.Fprintf(r.StdErr, "Failed to resolve SVC address: %s\n", err)
				return nil
			}
			resolved, ok := entries[hs]
			if !ok {
				fmt.Fprintf(r.StdErr, "No SVC address found. [svc=%s]", hs)
				return nil
			}
			// Filter the returned addresses.
			addrs := make([]resolver.Address, 0, len(resolved))
			for _, addr := range resolved {
				_, _, err := net.SplitHostPort(addr)
				if err != nil {
					fmt.Fprintf(r.StdErr, "Failed to parse addr %s: %s", addr, err)
					continue
				}
				addrs = append(addrs, resolver.Address{Addr: addr})
			}
			// Check if localhost is part of the filtered list and if yes, move
			// it to the front.
			for i, a := range addrs {
				h, _, err := net.SplitHostPort(a.Addr)
				if err != nil {
					// We already made sure that the address is valid.
					panic(err)
				}
				if h == r.LocalIP.String() {
					addrs[0], addrs[i] = addrs[i], addrs[0]
					break
				}
			}
			return addrs
		},
	}

	return r.doRequest(ctx, dialer, remote, req)
}

func (r *renewer) requestRemote(
	ctx context.Context,
	req *cppb.ChainRenewalRequest,
	remote net.Addr,
	ca addr.IA,
) ([]*x509.Certificate, error) {

	path, err := path.Choose(ctx, r.Daemon, ca, r.PathOptions()...)
	if err != nil {
		return nil, err
	}
	var dst net.Addr
	switch r := remote.(type) {
	case *snet.UDPAddr:
		dst = &snet.UDPAddr{
			IA:      ca,
			Host:    r.Host,
			Path:    path.Dataplane(),
			NextHop: path.UnderlayNextHop(),
		}
	case *snet.SVCAddr:
		dst = &snet.SVCAddr{
			IA:      ca,
			SVC:     r.SVC,
			Path:    path.Dataplane(),
			NextHop: path.UnderlayNextHop(),
		}
	default:
		panic(fmt.Sprintf("unsupported remote address: %s", remote))
	}

	localIP := r.LocalIP
	nexthop := path.UnderlayNextHop()
	if localIP == nil {
		// Resolve local IP based on underlay next hop
		if nexthop != nil {
			if localIP, err = addrutil.ResolveLocal(nexthop.IP); err != nil {
				return nil, serrors.Wrap("resolving local address", err)
			}
		} else {
			if localIP, err = addrutil.DefaultLocalIP(ctx, r.Daemon); err != nil {
				return nil, serrors.Wrap("resolving default address", err)
			}
		}
		fmt.Printf("Resolved local address:\n  %s\n", localIP)
	}
	local := &snet.UDPAddr{
		IA:   r.LocalIA,
		Host: &net.UDPAddr{IP: localIP},
	}

	sn := &snet.SCIONNetwork{
		Topology: r.Daemon,
		SCMPHandler: snet.SCMPPropagationStopper{
			Handler: snet.DefaultSCMPHandler{
				RevocationHandler: daemon.RevHandler{Connector: r.Daemon},
			},
			Log: log.FromCtx(ctx).Debug,
		},
	}

	conn, err := sn.Listen(ctx, "udp", local.Host)
	if err != nil {
		return nil, serrors.Wrap("dialing", err)
	}
	defer conn.Close()

	dialer := &grpc.QUICDialer{
		Rewriter: &infraenv.AddressRewriter{
			Router: &snet.BaseRouter{
				Querier: daemon.Querier{Connector: r.Daemon, IA: local.IA},
			},
			SVCRouter: svcRouter{Connector: r.Daemon},
			Resolver: &svc.Resolver{
				LocalIA: local.IA,
				Network: sn,
				LocalIP: local.Host.IP,
			},
		},
		Dialer: squic.ConnDialer{
			Transport: &quic.Transport{Conn: conn},
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"SCION"},
			},
		},
	}

	return r.doRequest(ctx, dialer, dst, req)
}

func (r *renewer) doRequest(
	ctx context.Context,
	dialer grpc.Dialer,
	remote net.Addr,
	req *cppb.ChainRenewalRequest,
) ([]*x509.Certificate, error) {

	c, err := dialer.Dial(ctx, remote)
	if err != nil {
		return nil, serrors.Wrap("dialing gRPC connection", err, "remote", remote)
	}
	defer c.Close()
	client := cppb.NewChainRenewalServiceClient(c)
	reply, err := client.ChainRenewal(ctx, req, grpc.RetryProfile...)
	if err != nil {
		return nil, serrors.Wrap("requesting certificate chain", err, "remote", c.Target())
	}
	renewed, err := extractChain(reply)
	if err != nil {
		return nil, serrors.Wrap("extracting certificate chain from response", err)
	}
	return renewed, nil
}

func encodeChain(chain []*x509.Certificate) []byte {
	var buffer bytes.Buffer
	for _, c := range chain {
		if err := pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			panic(err.Error())
		}
	}
	return buffer.Bytes()
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

func loadChain(trcs []*cppki.TRC, file string) ([]*x509.Certificate, error) {
	chain, err := cppki.ReadPEMCerts(file)
	if err != nil {
		return nil, err
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: trcs}); err != nil {
		if maybeMissingTRCInGrace(trcs) {
			fmt.Println("Verification failed, but current time still in Grace Period of latest TRC")
			fmt.Printf("Try to verify with the predecessor TRC: (Base = %d, Serial = %d)\n",
				trcs[0].ID.Base, trcs[0].ID.Serial-1)
		}
		return nil, serrors.Wrap(
			"verification of transport cert failed with provided TRC", err)

	}
	return chain, nil
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
		return nil, serrors.Wrap("parsing AS certificate", err)
	}
	if chain[1], err = x509.ParseCertificate(replyBody.Chain.CaCert); err != nil {
		return nil, serrors.Wrap("parsing CA certificate", err)
	}
	if err := cppki.ValidateChain(chain); err != nil {
		return nil, err
	}
	return chain, nil
}

func subjectFromVars(vars SubjectVars) (pkix.Name, error) {
	if vars.IA.IsZero() {
		return pkix.Name{}, serrors.New("isd_as required in template")
	}
	s := pkix.Name{
		CommonName:   vars.CommonName,
		SerialNumber: vars.SerialNumber,
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type:  cppki.OIDNameIA,
				Value: vars.IA.String(),
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

type svcRouter struct {
	Connector daemon.Connector
}

func (r svcRouter) GetUnderlay(svc addr.SVC) (*net.UDPAddr, error) {
	// XXX(karampok). We need to change the interface to not use TODO context.
	return daemon.TopoQuerier{Connector: r.Connector}.UnderlayAnycast(context.TODO(), svc)
}

func maybeMissingTRCInGrace(trcs []*cppki.TRC) bool {
	return len(trcs) == 1 && trcs[0].InGracePeriod(time.Now())
}
