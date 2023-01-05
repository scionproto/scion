// Copyright 2018 Anapaya Systems
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

package progress

import (
	"net"
	"net/http"
	"net/rpc"

	"github.com/scionproto/scion/pkg/addr"
)

// RPC defines the progress RPC API.
type RPC struct {
	onDone func(src, dst addr.IA)
}

// Done exposes the RPC.
func (r *RPC) Done(done *Done, rep *bool) error {
	*rep = true
	r.onDone(done.Src, done.Dst)
	return nil
}

// Done is the RPC call to indicate a test is done.
type Done struct {
	Src, Dst addr.IA
}

// Client is the client side of the RPCs between the testing binary and the
// integration test.
type Client struct {
	Socket string
}

// Done tells the integration test, that the testing binary is done.
func (c Client) Done(src, dst addr.IA) error {
	client, err := rpc.DialHTTP("unix", c.Socket)
	if err != nil {
		return err
	}
	args := &Done{Src: src, Dst: dst}
	var ignore bool
	return client.Call("RPC.Done", args, &ignore)
}

// Server is the server side of the RPCs between the testing binary and the
// integration test.
type Server struct {
	OnDone func(src, dst addr.IA)
}

// Serve starts serving the RPCs.
func (s *Server) Serve(l net.Listener) error {
	if err := rpc.Register(&RPC{onDone: s.OnDone}); err != nil {
		return err
	}
	rpc.HandleHTTP()
	return http.Serve(l, nil)
}
