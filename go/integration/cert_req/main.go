// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package main

import (
	"context"
	"flag"
	"net"
	"os"

	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/tracing"
)

var (
	remoteIA addr.IA
	svc      net.Addr
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.HandlePanic()
	defer log.Flush()
	addFlags()
	integration.Setup()

	closeTracer, err := integration.InitTracer("cert_req")
	if err != nil {
		log.Crit("Unable to create tracer", "err", err)
		return 1
	}
	defer closeTracer()
	return client{}.run()
}

func addFlags() {
	flag.Var((*addr.IA)(&remoteIA), "remoteIA", "(Mandatory) IA to fetch certs for")
}

type client struct {
	conn *snet.Conn
	msgr infra.Messenger
}

func (c client) run() int {
	network := integration.InitNetwork()
	var err error
	c.conn, err = network.Listen(context.Background(), "udp",
		integration.Local.Host, addr.SvcNone)
	if err != nil {
		integration.LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Send on", "local", c.conn.LocalAddr())
	c.msgr = messenger.New(
		&messenger.Config{
			IA: integration.Local.IA,
			Dispatcher: disp.New(
				c.conn,
				messenger.DefaultAdapter,
				log.Root(),
			),
			AddressRewriter: &messenger.AddressRewriter{
				Router: &snet.BaseRouter{
					Querier: snet.IntraASPathQuerier{IA: integration.Local.IA},
				},
			},
		},
	)
	if err = getRemote(); err != nil {
		integration.LogFatal("Error finding remote address", err)
	}
	return integration.AttemptRepeatedly("Cert request", c.attemptRequest)
}

func (c client) attemptRequest(n int) bool {
	span, ctx := tracing.CtxWith(context.Background(), "run")
	span.SetTag("attempt", n)
	span.SetTag("src", integration.Local.IA)
	span.SetTag("subject", remoteIA)
	defer span.Finish()

	// Send certchain request
	var chain *cert.Chain
	var err error
	if chain, err = c.requestCert(ctx); err != nil {
		log.Error("Error requesting certificate chain", "err", err)
		ext.Error.Set(span, true)
		return false
	}
	// Send TRC request
	if err = c.requestTRC(ctx, chain); err != nil {
		log.Error("Error requesting TRC", "err", err)
		ext.Error.Set(span, true)
		return false
	}
	return true
}

func (c client) requestCert(parentCtx context.Context) (*cert.Chain, error) {
	logger := log.FromCtx(parentCtx)
	req := &cert_mgmt.ChainReq{
		RawIA:   remoteIA.IAInt(),
		Version: scrypto.LatestVer,
	}
	logger.Info("Request to SVC: Chain request", "req", req, "svc", svc)
	ctx, cancelF := context.WithTimeout(parentCtx, integration.DefaultIOTimeout)
	defer cancelF()
	rawChain, err := c.msgr.GetCertChain(ctx, req, svc, messenger.NextId())
	if err != nil {
		return nil, common.NewBasicError("Unable to get chain", err)
	}
	chain, err := cert.ParseChain(rawChain.RawChain)
	if err != nil {
		return nil, common.NewBasicError("Unable to parse chain", err)
	}
	as, err := chain.AS.Encoded.Decode()
	if err != nil {
		return nil, common.NewBasicError("Unable to parse AS certificate", err)
	}
	if !as.Subject.Equal(remoteIA) {
		return nil, common.NewBasicError("Invalid subject", nil,
			"expected", remoteIA, "actual", as.Subject)
	}
	logger.Info("Response from SVC: Correct chain", "chain", chain)
	return &chain, nil
}

func (c client) requestTRC(parentCtx context.Context, chain *cert.Chain) error {
	logger := log.FromCtx(parentCtx)
	req := &cert_mgmt.TRCReq{
		ISD:     remoteIA.I,
		Version: scrypto.LatestVer,
	}
	logger.Info("Request to SVC: TRC request", "req", req, "svc", svc)
	ctx, cancelF := context.WithTimeout(parentCtx, integration.DefaultIOTimeout)
	defer cancelF()
	rawTrc, err := c.msgr.GetTRC(ctx, req, svc, messenger.NextId())
	if err != nil {
		return common.NewBasicError("Unable to get trc", err)
	}
	signed, err := trc.ParseSigned(rawTrc.RawTRC)
	if err != nil {
		return common.NewBasicError("Unable to parse signed trc", err)
	}
	trc, err := signed.EncodedTRC.Decode()
	if err != nil {
		return common.NewBasicError("Unable to parse trc payload", err)
	}
	if trc.ISD != remoteIA.I {
		return common.NewBasicError("Invalid ISD", nil,
			"expected", remoteIA.I, "actual", trc.ISD)
	}
	if err := c.verifyChain(chain, trc); err != nil {
		return common.NewBasicError("unable to verify chain", err)
	}
	logger.Info("Response from SVC: Correct TRC", "TRC", trc)
	return nil
}

func (c client) verifyChain(chain *cert.Chain, t *trc.TRC) error {
	as, err := chain.AS.Encoded.Decode()
	if err != nil {
		return common.NewBasicError("unable to parse AS certificate", err)
	}
	if err := as.Validate(); err != nil {
		return common.NewBasicError("unable to validate AS certificate", err)
	}
	iss, err := chain.Issuer.Encoded.Decode()
	if err != nil {
		return common.NewBasicError("unable to parse issuer certificate", err)
	}
	if err := iss.Validate(); err != nil {
		return common.NewBasicError("unable to validate issuer certificate", err)
	}
	issVerifier := cert.IssuerVerifier{
		Issuer:       iss,
		SignedIssuer: &chain.Issuer,
		TRC:          t,
	}
	if err := issVerifier.Verify(); err != nil {
		return common.NewBasicError("unable to verify issuer certificate", err)
	}
	asVerifier := cert.ASVerifier{
		Issuer:   iss,
		SignedAS: &chain.AS,
		AS:       as,
	}
	if err := asVerifier.Verify(); err != nil {
		return common.NewBasicError("unable to verify issuer certificate", err)
	}
	return nil
}

func getRemote() error {
	// Fetch address of service
	var svcHost *net.UDPAddr
	var err error
	if svcHost, err = getSVCAddress(); err != nil {
		return err
	}
	svc = &snet.UDPAddr{IA: integration.Local.IA, Host: svcHost}
	return nil
}

func getSVCAddress() (*net.UDPAddr, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()
	return sciond.TopoQuerier{Connector: integration.SDConn()}.UnderlayAnycast(ctx, addr.SvcCS)
}
