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

package hiddenpath

import (
	"context"
	"net"
)

// Servers is a list of discovered remote hidden segment server.
type Servers struct {
	// Lookup is the list of lookup addresses.
	Lookup []*net.UDPAddr
	// Registration is the list of registration addresses.
	Registration []*net.UDPAddr
}

// Discoverer can be used to find remote discovery services.
type Discoverer interface {
	Discover(ctx context.Context, dsAddr net.Addr) (Servers, error)
}
