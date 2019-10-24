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

package segreq

import (
	"context"

	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/serrors"
)

// BaseValidator is the base validation for all PSes.
type BaseValidator struct {
	CoreChecker
}

// Validate validates the request.
func (v *BaseValidator) Validate(ctx context.Context, r segfetcher.Request) error {
	wildSrc := r.Src.IsWildcard()
	wildDst := r.Dst.IsWildcard()
	sameIsd := r.Src.I == r.Dst.I
	coreSrc, err := v.IsCore(ctx, r.Src)
	if err != nil {
		return err
	}
	coreDst, err := v.IsCore(ctx, r.Dst)
	if err != nil {
		return err
	}
	switch {
	case r.IsZero() || r.Src.IsZero() || r.Dst.IsZero():
		return serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"req", r, "reason", "zero src or dst")
	case wildSrc && wildDst:
		return serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"req", r, "reason", "wildcard src & dst")
	case !coreSrc && (coreDst || wildDst) && sameIsd:
		// up segment
		return nil
	case coreSrc && coreDst:
		// core segment
		return nil
	case (coreSrc || wildSrc) && !coreDst && sameIsd:
		// down segment
		return nil
	default:
		return serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"req", r, "reason", "not a single segment")
	}
}

// CoreValidator is the validator for core PSes.
type CoreValidator struct {
	BaseValidator
}

// Validate validates the request.
func (v *CoreValidator) Validate(ctx context.Context, r segfetcher.Request) error {
	if err := v.BaseValidator.Validate(ctx, r); err != nil {
		return err
	}
	coreSrc, err := v.IsCore(ctx, r.Src)
	if err != nil {
		return err
	}
	if !coreSrc {
		return serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"req", r, "reason", "src should be core")
	}
	return nil
}
