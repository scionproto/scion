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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
)

// Registry handles registrations.
type Registry interface {
	Register(context.Context, Registration) error
}

// Registration is a hidden segment registration.
type Registration struct {
	// Segments are the segments to be registered.
	Segments []*seg.Meta
	// GroupID is the hiddenpath group ID under which the segments should be
	// registered.
	GroupID GroupID
	// Peer is the address of the writer of the segments.
	Peer *snet.SVCAddr
}

// RegistryServer handles hidden segment registrations.
type RegistryServer struct {
	// Groups is the current set of groups.
	Groups map[GroupID]*Group
	// DB is used to write received segments.
	DB Store
	// Verifier is used to verify the received segments.
	Verifier Verifier
	// LocalIA is the IA this handler is in.
	LocalIA addr.IA
}

// Register registers the given registration.
func (h RegistryServer) Register(ctx context.Context, reg Registration) error {
	// validate first
	group, ok := h.Groups[reg.GroupID]
	if !ok {
		return serrors.New("unknown group")
	}
	if _, ok := group.Writers[reg.Peer.IA]; !ok {
		return serrors.New("sender not writer in group")
	}
	if _, ok := group.Registries[h.LocalIA]; !ok {
		return serrors.New("receiver not registry in group")
	}
	for _, s := range reg.Segments {
		if s.Type != seg.TypeDown {
			return serrors.New("wrong segment type", "segment", s, "expected", seg.TypeDown)
		}
	}

	// verify segments
	if err := h.Verifier.Verify(ctx, reg.Segments, reg.Peer); err != nil {
		return serrors.Wrap("verifying segments", err)
	}
	// store segments in db
	if err := h.DB.Put(ctx, reg.Segments, reg.GroupID); err != nil {
		return serrors.Wrap("writing segments", err)
	}
	return nil
}
