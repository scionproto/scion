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

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

var (
	remoteIA addr.IA
	svc      snet.Addr
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.LogPanicAndExit()
	defer log.Flush()
	addFlags()
	integration.Setup()
	return client{}.run()
}

func addFlags() {
	flag.Var((*addr.IA)(&remoteIA), "remoteIA", "(Mandatory) IA to fetch certs for")
}

type client struct {
	conn snet.Conn
	msgr infra.Messenger
}

func (c client) run() int {
	network := integration.InitNetwork()
	var err error
	c.conn, err = network.ListenSCION("udp4", &integration.Local, 0)
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
				Router: &snet.BaseRouter{IA: integration.Local.IA},
			},
		},
	)
	if err = getRemote(); err != nil {
		integration.LogFatal("Error finding remote address", err)
	}
	return integration.AttemptRepeatedly("Cert request", c.attemptRequest)
}

func (c client) attemptRequest(n int) bool {
	// Send certchain request
	var chain *cert.Chain
	var err error
	if chain, err = c.requestCert(); err != nil {
		log.Error("Error requesting certificate chain", "err", err)
		return false
	}
	// Send TRC request
	if err = c.requestTRC(chain); err != nil {
		log.Error("Error requesting TRC", "err", err)
		return false
	}
	return true
}

func (c client) requestCert() (*cert.Chain, error) {
	req := &cert_mgmt.ChainReq{
		CacheOnly: false,
		RawIA:     remoteIA.IAInt(),
		Version:   scrypto.LatestVer,
	}
	log.Info("Request to SVC: Chain request", "req", req, "svc", svc)
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()
	rawChain, err := c.msgr.GetCertChain(ctx, req, &svc, messenger.NextId())
	if err != nil {
		return nil, common.NewBasicError("Unable to get chain", err)
	}
	chain, err := rawChain.Chain()
	if err != nil {
		return nil, common.NewBasicError("Unable to parse chain", err)
	}
	if chain == nil {
		return nil, serrors.New("Empty reply")
	}
	if !chain.Leaf.Subject.Equal(remoteIA) {
		return nil, common.NewBasicError("Invalid subject", nil,
			"expected", remoteIA, "actual", chain.Leaf.Subject)
	}
	log.Info("Response from SVC: Correct chain", "chain", chain)
	return chain, nil
}

func (c client) requestTRC(chain *cert.Chain) error {
	req := &cert_mgmt.TRCReq{
		CacheOnly: false,
		ISD:       remoteIA.I,
		Version:   scrypto.LatestVer,
	}
	log.Info("Request to SVC: TRC request", "req", req, "svc", svc)
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()
	rawTrc, err := c.msgr.GetTRC(ctx, req, &svc, messenger.NextId())
	if err != nil {
		return common.NewBasicError("Unable to get trc", err)
	}
	trc, err := rawTrc.TRC()
	if err != nil {
		return common.NewBasicError("Unable to parse trc", err)
	}
	if trc == nil {
		return serrors.New("Empty reply")
	}
	if trc.ISD != remoteIA.I {
		return common.NewBasicError("Invalid ISD", nil,
			"expected", remoteIA.I, "actual", trc.ISD)
	}
	if err := chain.Verify(remoteIA, trc); err != nil {
		return common.NewBasicError("Certificate verification failed", err)
	}
	log.Info("Response from SVC: Correct TRC", "TRC", trc)
	return nil
}

func getRemote() error {
	// Fetch address of service
	var svcHost *net.UDPAddr
	var err error
	if svcHost, err = getSVCAddress(); err != nil {
		return err
	}
	svc = snet.Addr{IA: integration.Local.IA, Host: addr.AppAddrFromUDP(svcHost)}
	return nil
}

func getSVCAddress() (*net.UDPAddr, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()
	reply, err := integration.SDConn().SVCInfo(ctx, []proto.ServiceType{proto.ServiceType_cs})
	if err != nil {
		return nil, err
	}
	return reply.Entries[0].HostInfos[0].UDP(), nil
}
