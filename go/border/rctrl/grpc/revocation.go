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

// RevocationSender can be used to send revocations.
type RevocationSender struct {
	// Dialer dials a new gRPC connection.
	Dialer grpc.Dialer

	// SendCounter counts each sent revocation, must not be nil.
	SendCounter metrics.Counter
	// Logger is used for logging, must not be nil.
	Logger log.Logger
}

func (s RevocationSender) SendRevocation(ctx context.Context,
	revocation *path_mgmt.SignedRevInfo, servers []net.Addr) error {

	var wg sync.WaitGroup
	errCh := make(chan error, len(servers))
	for _, server := range servers {
		server := server
		wg.Add(1)
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			if err := s.sendRevocation(ctx, revocation, server); err != nil {
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
	s.Logger.Debug("Sent revocations", "dsts", servers, "err", err)
	return err
}

func (s RevocationSender) sendRevocation(ctx context.Context,
	revocation *path_mgmt.SignedRevInfo, server net.Addr) error {

	labels := revLabels{Result: "err_process", SVC: "CS"}
	rawRev, err := revocation.Pack()
	if err != nil {
		s.SendCounter.With(labels.Expand()...).Add(1)
		return serrors.WrapStr("packing RevInfo", err, "server", server)
	}
	labels.Result = "err_write"
	conn, err := s.Dialer.Dial(ctx, server)
	if err != nil {
		s.SendCounter.With(labels.Expand()...).Add(1)
		return serrors.WrapStr("dialing", err, "server", server)
	}
	defer conn.Close()
	client := cppb.NewInterfaceStateServiceClient(conn)
	_, err = client.SignedRevocation(ctx, &cppb.SignedRevocationRequest{Raw: rawRev})
	if err != nil {
		s.SendCounter.With(labels.Expand()...).Add(1)
		return serrors.WrapStr("sending revocation", err, "server", server)
	}
	labels.Result = "ok_success"
	s.SendCounter.With(labels.Expand()...).Add(1)
	return nil
}

type revLabels struct {
	Result string
	SVC    string
}

func (l revLabels) Expand() []string {
	return []string{
		"result", l.Result,
		"svc", l.SVC,
	}
}
