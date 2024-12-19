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

package grpc

import (
	"context"
	"net"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	gpb "github.com/scionproto/scion/pkg/proto/gateway"
)

// ProbeDispatcher handles incoming gateway protocol messages.
// Currently, it only supports probe requests, and immediately replies to them.
type ProbeDispatcher struct {
}

// Listen handles the received control requests.
func (d *ProbeDispatcher) Listen(ctx context.Context, conn net.PacketConn) error {
	logger := log.FromCtx(ctx)
	logger.Info("ProbeDispatcher: starting")
	defer logger.Info("ProbeDispatcher: stopped")

	buf := make([]byte, common.SupportedMTU)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				logger.Info("ProbeDispatcher: Error reading from connection", "err", err)
				// FIXME(shitz): Continuing here is only a temporary solution. Different
				// errors need to be handled different, for some it should break and others
				// are recoverable.
				continue
			}
			if err = d.dispatch(conn, buf[:n], addr); err != nil {
				logger.Info("ProbeDispatcher: Error dispatching", "addr", addr, "err", err)
			}
		}
	}
}

func (d *ProbeDispatcher) dispatch(conn net.PacketConn, raw []byte, addr net.Addr) error {
	var ctrl gpb.ControlRequest
	if err := proto.Unmarshal(raw, &ctrl); err != nil {
		return err
	}
	switch c := ctrl.Request.(type) {
	case *gpb.ControlRequest_Probe:
		reply := &gpb.ControlResponse{
			Response: &gpb.ControlResponse_Probe{
				Probe: &gpb.ProbeResponse{
					SessionId: c.Probe.SessionId,
					Data:      c.Probe.Data,
				},
			},
		}
		packed, err := proto.Marshal(reply)
		if err != nil {
			return serrors.Wrap("packing probe response", err, "session_id", c.Probe.SessionId)
		}
		_, err = conn.WriteTo(packed, addr)
		return err
	default:
		return serrors.New("unexpected control request", "type", common.TypeOf(ctrl.Request))
	}
}
