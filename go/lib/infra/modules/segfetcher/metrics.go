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

package segfetcher

import (
	"errors"

	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ErrToMetricsLabel classifies the error from the segfetcher into metrics
// labels.
func ErrToMetricsLabel(err error) string {
	switch {
	case serrors.IsTimeout(err):
		return prom.ErrTimeout
	case errors.Is(err, errDB), errors.Is(err, seghandler.ErrDB):
		return prom.ErrDB
	case errors.Is(err, errFetch):
		return prom.ErrNetwork
	case errors.Is(err, seghandler.ErrVerification):
		return prom.ErrVerify
	default:
		return prom.ErrNotClassified
	}
}
