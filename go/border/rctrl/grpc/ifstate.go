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
	"sync"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// InterfaceState denotes the state of a single interface
type InterfaceState struct {
	// ID identifies the interface.
	ID uint64
	// Revocation indicates the state of the interface.
	Revocation *path_mgmt.SignedRevInfo
}

// IfStateHandler handles the interface state update.
type IfStateHandler interface {
	UpdateState([]InterfaceState)
}

// IfStateUpdater fetch interface state information via gRPC.
type IfStateUpdater struct {
	// Dialer dials a new gRPC connection.
	Dialer grpc.Dialer
	// Handler is used to handle the replies, must not be nil.
	Handler IfStateHandler

	// IfStateTicker counts each call to UpdateIfState, must not be nil.
	IfStateTicker metrics.Counter
	// SendCounter counts each sent request, must not be nil.
	SendCounter metrics.Counter
	// ReceiveCounter counts each reply received, must not be nil.
	ReceiveCounter metrics.Counter
	// ProcessErrors counts the parsing errors, must not be nil.
	ProcessErrors metrics.Counter
	// Logger is used to log, must not be nil.
	Logger log.Logger
}

func (u IfStateUpdater) UpdateIfState(ctx context.Context, servers []net.Addr) error {
	u.IfStateTicker.Add(1)

	var wg sync.WaitGroup
	errCh := make(chan error, len(servers))
	for _, s := range servers {
		s := s
		wg.Add(1)
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			if err := u.updateIfState(ctx, s); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	var errors serrors.List
	for err := range errCh {
		errors = append(errors, err)
	}
	err := errors.ToError()
	u.Logger.Debug("Updated interface state", "servers", servers, "err", err)
	return err
}

func (u IfStateUpdater) updateIfState(ctx context.Context, server net.Addr) error {
	conn, err := u.Dialer.Dial(ctx, server)
	if err != nil {
		u.SendCounter.With("result", "err_write").Add(1)
		return serrors.WrapStr("dialing", err, "server", server)
	}
	defer conn.Close()
	client := cppb.NewInterfaceStateServiceClient(conn)
	reply, err := client.InterfaceState(ctx, &cppb.InterfaceStateRequest{})
	if err != nil {
		u.SendCounter.With("result", "err_write").Add(1)
		return err
	}
	u.SendCounter.With("result", "ok_success").Add(1)
	u.ReceiveCounter.With("result", "ok_success").Add(1)
	states := make([]InterfaceState, 0, len(reply.States))
	for _, s := range reply.States {
		var rev *path_mgmt.SignedRevInfo
		if len(s.SignedRev) > 0 {
			var err error
			rev, err = path_mgmt.NewSignedRevInfoFromRaw(s.SignedRev)
			if err != nil {
				u.ProcessErrors.With("result", "err_parse").Add(1)
				return err
			}
		}
		states = append(states, InterfaceState{
			ID:         s.Id,
			Revocation: rev,
		})
	}
	u.Handler.UpdateState(states)
	return nil
}
