// Copyright 2018 ETH Zurich, Anapaya Systems
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

// This file implements the Control Plane

package rctrl

import (
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/scionproto/scion/go/border/ifstate"
	"github.com/scionproto/scion/go/border/metrics"
	rctrlgrpc "github.com/scionproto/scion/go/border/rctrl/grpc"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	libmetrics "github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

const (
	maxBufSize = 9 * 1024
)

var (
	ia     addr.IA
	logger log.Logger
)

func Control(sRevInfoQ chan rpkt.RawSRevCallbackArgs) {
	logger = log.New("Part", "Control")
	ctx := rctx.Get()
	ia = ctx.Conf.IA
	ctrlAddr := ctx.Conf.BR.CtrlAddrs.SCIONAddress
	grpcAddr := &net.TCPAddr{IP: ctrlAddr.IP, Port: ctrlAddr.Port, Zone: ctrlAddr.Zone}
	if _, disableUpdate := os.LookupEnv("SCION_BR_DISABLE_IFSTATE_MGMT"); disableUpdate {
		log.Info("interface state mgmt disabled")
		return
	}
	go func() {
		defer log.HandlePanic()
		updater := rctrlgrpc.IfStateUpdater{
			Dialer:         libgrpc.SimpleDialer{},
			Handler:        ifstate.StateHandler{},
			IfStateTicker:  libmetrics.NoWith(metrics.Control.IFStateTick()),
			SendCounter:    libmetrics.NewPromCounter(metrics.Control.SendIFStateReqVec()),
			ReceiveCounter: libmetrics.NewPromCounter(metrics.Control.ReceivedIFStateInfoVec()),
			ProcessErrors:  libmetrics.NewPromCounter(metrics.Control.ProcessErrorsVec()),
			Logger:         log.Root(),
		}
		ifStateUpdate(updater)
	}()
	go func() {
		defer log.HandlePanic()
		sender := rctrlgrpc.RevocationSender{
			Dialer:      libgrpc.SimpleDialer{},
			SendCounter: libmetrics.NewPromCounter(metrics.Control.SentRevInfosVec()),
			Logger:      log.Root(),
		}
		revInfoFwd(sRevInfoQ, sender)
	}()
	if err := processCtrl(grpcAddr); err != nil {
		fatal.Fatal(serrors.WrapStr("serving grpc", err))
	}
}

func processCtrl(a net.Addr) error {
	log.Debug("Listening for gRPC", "addr", a)
	routerListener, err := net.Listen("tcp", a.String())
	if err != nil {
		return serrors.WrapStr("listening", err)
	}
	routerServer := grpc.NewServer()
	cppb.RegisterInterfaceStateConsumerServiceServer(routerServer, rctrlgrpc.IfStateConsumerServer{
		Handler: ifstate.StateHandler{},
	})
	return routerServer.Serve(routerListener)
}
