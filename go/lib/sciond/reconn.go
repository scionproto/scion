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

package sciond

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/proto"
)

var _ Connector = (*reconnector)(nil)

// reconnector is a SCIOND API implementation that is resilient to SCIOND going
// down and up.
//
// It achieves the above property by establishing a connection for each API
// call.
//
// XXX(scrye): The underlying one-shot SCIOND API connection has an infra
// dispatcher layered on top of the unix transport communication with sciond.
// This is not necessary for request-response matching, but is useful for
// context.Context support. If performance becomes an issue, an improvement
// might be to have a lightweight implementation that just ensures context
// support.
type reconnector struct {
	path string
}

func newReconnector(path string, initialCheckTimeout time.Duration) (*reconnector, error) {
	c := &reconnector{path: path}
	// Test during initialization that SCIOND is alive; this helps catch some
	// unfixable issues (like bad socket name) while apps are still
	// initializing their networking.
	if err := c.checkForSciond(initialCheckTimeout); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *reconnector) checkForSciond(initialCheckTimeout time.Duration) error {
	sciondConn, err := connectTimeout(c.path, initialCheckTimeout)
	if err != nil {
		return common.NewBasicError("Unable to connect to SCIOND", err)
	}
	if err := sciondConn.Close(context.Background()); err != nil {
		return common.NewBasicError("Error when closing test SCIOND conn", err)
	}
	return nil
}

func (c *reconnector) Paths(ctx context.Context, dst, src addr.IA, max uint16,
	f PathReqFlags) (*PathReply, error) {

	conn, err := c.ctxAwareConnect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	return conn.Paths(ctx, dst, src, max, f)
}

func (c *reconnector) ASInfo(ctx context.Context, ia addr.IA) (*ASInfoReply, error) {
	conn, err := c.ctxAwareConnect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	return conn.ASInfo(ctx, ia)
}

func (c *reconnector) IFInfo(ctx context.Context, ifs []common.IFIDType) (*IFInfoReply, error) {
	conn, err := c.ctxAwareConnect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	return conn.IFInfo(ctx, ifs)
}

func (c *reconnector) SVCInfo(ctx context.Context,
	svcTypes []proto.ServiceType) (*ServiceInfoReply, error) {

	conn, err := c.ctxAwareConnect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	return conn.SVCInfo(ctx, svcTypes)
}

func (c *reconnector) RevNotificationFromRaw(ctx context.Context, b []byte) (*RevReply, error) {
	conn, err := c.ctxAwareConnect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	return conn.RevNotificationFromRaw(ctx, b)
}

func (c *reconnector) RevNotification(ctx context.Context,
	sRevInfo *path_mgmt.SignedRevInfo) (*RevReply, error) {

	conn, err := c.ctxAwareConnect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	return conn.RevNotification(ctx, sRevInfo)
}

func (c *reconnector) Close(ctx context.Context) error {
	return nil
}

func (c *reconnector) ctxAwareConnect(ctx context.Context) (Connector, error) {
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = deadline.Sub(time.Now())
		if timeout < 0 {
			timeout = 0
		}
	}

	type returnValue struct {
		conn Connector
		err  error
	}
	barrier := make(chan returnValue, 1)
	go func() {
		conn, err := connectTimeout(c.path, timeout)
		barrier <- returnValue{conn: conn, err: err}
	}()

	select {
	case rValue := <-barrier:
		return rValue.conn, rValue.err
	case <-ctx.Done():
		// In the situation where ConnectTimeout doesn't finish and ctx is Done
		// via a cancellation function, this may (1) permanently leak a
		// goroutine, if ctx doesn't have a deadline, or (2) for a long amount
		// of time, if the deadline is very far into the future.
		return nil, ctx.Err()
	}
}
