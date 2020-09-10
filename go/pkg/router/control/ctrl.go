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

package control

import (
	"net"

	"google.golang.org/grpc"

	rctrlgrpc "github.com/scionproto/scion/go/border/rctrl/grpc"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

func processCtrl(c *IACtx) {
	a := c.BRConf.BR.CtrlAddrs.SCIONAddress
	log.Debug("Listening for gRPC", "addr", a)
	routerListener, err := net.Listen("tcp", a.String())
	if err != nil {
		fatal.Fatal(serrors.WrapStr("listening", err))
	}
	routerServer := grpc.NewServer()
	cppb.RegisterInterfaceStateConsumerServiceServer(routerServer, rctrlgrpc.IfStateConsumerServer{
		Handler: StateHandler{c: c},
	})

	if err := routerServer.Serve(routerListener); err != nil {
		fatal.Fatal(err)
	}
}
