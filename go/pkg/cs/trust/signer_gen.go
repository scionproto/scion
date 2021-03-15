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

package trust

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/cs/trust/metrics"
	"github.com/scionproto/scion/go/pkg/trust"
)

// CachingSignerGen is a SignerGen that can cache the previously
// generated Signer for some time.
type CachingSignerGen struct {
	SignerGen SignerGen
	Interval  time.Duration

	mtx     sync.Mutex
	lastGen time.Time
	cached  trust.Signer
	ok      bool
}

// Generate generates a signer using the SignerGen or returns the cached signer.
// An error is only returned if the previous signer is empty, and no signer can
// be generated.
func (s *CachingSignerGen) Generate(ctx context.Context) (trust.Signer, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	now := time.Now()
	if now.Sub(s.lastGen) < s.Interval {
		if !s.ok {
			return trust.Signer{}, serrors.New("no signer cached, reload interval has not passed")
		}
		return s.cached, nil
	}
	s.lastGen = now
	signer, err := s.SignerGen.Generate(ctx)
	if err != nil {
		if !s.ok {
			return trust.Signer{}, err
		}
		log.FromCtx(ctx).Info("Failed to generate new signer, using previous signer", "err", err)
		return s.cached, nil
	}
	if !s.cached.Equal(signer) {
		log.FromCtx(ctx).Info("Generated new signer",
			"subject_key_id", fmt.Sprintf("%x", signer.SubjectKeyID),
			"expiration", signer.Expiration,
		)
	}

	s.cached, s.ok = signer, true

	metrics.Signer.LastGeneratedAS().SetToCurrentTime()
	metrics.Signer.ExpirationAS().Set(metrics.Timestamp(signer.Expiration))
	return s.cached, nil
}
