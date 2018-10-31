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

package main

import (
	"context"
	"os"
	"time"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.LogPanicAndExit()
	defer log.Flush()
	integration.Setup()
	return certClient{}.Run()
}

type certClient struct {
	conn snet.Conn
	msgr *messenger.Messenger
}

func (c certClient) Run() int {
	var err error
	c.conn, err = snet.ListenSCION("udp4", &integration.Local)
	if err != nil {
		integration.LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Send on", "local", c.conn.LocalAddr())
	c.msgr = messenger.New(
		integration.Local.IA,
		disp.New(
			transport.NewPacketTransport(c.conn),
			messenger.DefaultAdapter,
			log.Root(),
		), nil, log.Root(), nil,
	)
	if integration.Remote, err = getRemote(); err != nil {
		integration.LogFatal("Error finding remote address", err)
	}
	ticker := time.NewTicker(integration.RetryTimeout)
	defer ticker.Stop()
	tries := 0
	for range ticker.C {
		tries++
		if c.attemptRequest() {
			return 0
		} else if tries < integration.Attempts {
			log.Info("Retrying...")
			continue
		}
		log.Error("Cert request failed. No more attempts...")
		break
	}
	return 1
}

func (c certClient) attemptRequest() bool {
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

func (c certClient) requestCert() (*cert.Chain, error) {
	req := &cert_mgmt.ChainReq{
		CacheOnly: true,
		RawIA:     integration.Remote.IA.IAInt(),
		Version:   scrypto.LatestVer,
	}
	log.Info("Request to SVC: Chain request", "req", req, "remote", integration.Remote)
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()
	rawChain, err := c.msgr.GetCertChain(ctx, req, &integration.Remote, messenger.NextId())
	if err != nil {
		return nil, common.NewBasicError("Unable to get chain", err)
	}
	chain, err := rawChain.Chain()
	if err != nil {
		return nil, common.NewBasicError("Unable to parse chain", err)
	}
	if !chain.Leaf.Subject.Eq(integration.Remote.IA) {
		return nil, common.NewBasicError("Invalid subject", nil,
			"expected", integration.Remote.IA, "actual", chain.Leaf.Subject)
	}
	log.Info("Response from SVC: Correct chain", "chain", chain)
	return chain, nil
}

func (c certClient) requestTRC(chain *cert.Chain) error {
	req := &cert_mgmt.TRCReq{
		CacheOnly: true,
		ISD:       integration.Remote.IA.I,
		Version:   scrypto.LatestVer,
	}
	log.Info("Request to SVC: TRC request", "req", req, "remote", integration.Remote)
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()
	rawTrc, err := c.msgr.GetTRC(ctx, req, &integration.Remote, messenger.NextId())
	if err != nil {
		return common.NewBasicError("Unable to get trc", err)
	}
	trc, err := rawTrc.TRC()
	if err != nil {
		return common.NewBasicError("Unable to parse trc", err)
	}
	if trc.ISD != integration.Remote.IA.I {
		return common.NewBasicError("Invalid ISD", nil,
			"expected", integration.Remote.IA.I, "actual", trc.ISD)
	}
	if err := chain.Verify(integration.Remote.IA, trc); err != nil {
		return common.NewBasicError("Certificate verification failed", err)
	}
	log.Info("Response from SVC: Correct TRC", "TRC", trc)
	return nil
}

func getRemote() (snet.Addr, error) {
	if svc, ok := integration.Remote.Host.L3.(addr.HostSVC); ok {
		// Fetch address of service
		if integration.Remote.IA.Eq(integration.Local.IA) {
			var hostInfo *sciond.HostInfo
			var err error
			if hostInfo, err = getSVCAddress(); err != nil {
				return integration.Remote, err
			}
			appAddr := addr.AppAddr{L3: hostInfo.Host(), L4: addr.NewL4UDPInfo(hostInfo.Port)}
			return snet.Addr{IA: integration.Remote.IA, Host: &appAddr}, nil
		}
		return snet.Addr{IA: integration.Remote.IA, Host: addr.NewSVCUDPAppAddr(svc)}, nil
	}
	// Query a host directly
	return integration.Remote, nil
}

func getSVCAddress() (*sciond.HostInfo, error) {
	connector, err := snet.DefNetwork.Sciond().Connect()
	if err != nil {
		return nil, err
	}
	reply, err := connector.SVCInfo([]proto.ServiceType{proto.ServiceTypeFromString("cs")})
	if err != nil {
		return nil, err
	}
	return &reply.Entries[0].HostInfos[0], nil
}
