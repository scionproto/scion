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

package snet

import (
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// PacketDispatcherService constructs SCION sockets where applications have
// fine-grained control over header fields.
type PacketDispatcherService interface {
	RegisterTimeout(ia addr.IA, public *addr.AppAddr, bind *overlay.OverlayAddr,
		svc addr.HostSVC, timeout time.Duration) (PacketConn, uint16, error)
}

var _ PacketDispatcherService = (*DefaultPacketDispatcherService)(nil)

type DefaultPacketDispatcherService struct {
	dispatcherService reliable.DispatcherService
}

func NewDefaultPacketDispatcherService(
	dispatcherService reliable.DispatcherService) *DefaultPacketDispatcherService {

	return &DefaultPacketDispatcherService{
		dispatcherService: dispatcherService,
	}
}

func (s *DefaultPacketDispatcherService) RegisterTimeout(ia addr.IA, public *addr.AppAddr,
	bind *overlay.OverlayAddr, svc addr.HostSVC,
	timeout time.Duration) (PacketConn, uint16, error) {

	rconn, port, err := s.dispatcherService.Register(ia, public, bind, svc)
	if err != nil {
		return nil, 0, err
	}
	return NewSCIONPacketConn(rconn), port, err
}
