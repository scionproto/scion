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
	"errors"

	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
)

func errToLabel(err error) string {
	switch {
	case err == nil:
		return metrics.Success
	case errors.Is(err, ErrValidation):
		return metrics.ErrValidate
	case errors.Is(err, ErrContentMismatch), errors.Is(err, ErrVerification):
		return metrics.ErrVerify
	case errors.Is(err, ErrNotFound):
		return metrics.ErrNotFound
	case errors.Is(err, ErrInactive):
		return metrics.ErrInactive
	case errors.Is(err, decoded.ErrParse):
		return metrics.ErrParse
	default:
		return metrics.ErrInternal
	}
}
