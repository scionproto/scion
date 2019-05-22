// Copyright 2019 ETH Zurich
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

package rpc

import (
	"net"

	capnp "zombiezen.com/go/capnproto2"
)

type Request struct {
	Message *capnp.Message
	// Address records the network address that sent the request. It will
	// usually be used for logging.
	Address net.Addr
}

type Reply struct {
	Message *capnp.Message
}
