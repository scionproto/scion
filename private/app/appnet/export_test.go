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

package appnet

import (
	"context"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/svc"
)

func (r AddressRewriter) BuildFullAddress(ctx context.Context,
	a *snet.SVCAddr) (*snet.SVCAddr, error) {
	return r.buildFullAddress(ctx, a)
}

func (r AddressRewriter) ResolveSVC(ctx context.Context, p snet.Path,
	s addr.SVC) (snet.Path, *net.UDPAddr, error) {
	return r.resolveSVC(ctx, p, s)
}

func ParseReply(reply *svc.Reply) (*net.UDPAddr, error) {
	return parseReply(reply)
}
