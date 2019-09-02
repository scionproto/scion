// Copyright 2019 Anapaya Systems
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

package seghandler

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
)

// Verifier is used to verify a segment reply.
type Verifier interface {
	Verify(context.Context, Segments, net.Addr) (chan segverifier.UnitResult, int)
}

// DefaultVerifier is a convenience wrapper around segverifier that implements
// the Verifier interface.
type DefaultVerifier struct {
	Verifier infra.Verifier
}

// Verify calls segverifier for the given reply.
func (v *DefaultVerifier) Verify(ctx context.Context, recs Segments,
	server net.Addr) (chan segverifier.UnitResult, int) {

	return segverifier.StartVerification(ctx, v.Verifier, server, recs.Segs, recs.SRevInfos)
}
