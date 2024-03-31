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

package cppki

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// ErrInvalidValidityPeriod indicates an invalid validity period.
var ErrInvalidValidityPeriod = serrors.New("NotAfter before NotBefore")

// Validity indicates the TRC validity.
type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// Contains indicates whether the provided time is inside the validity period.
func (v Validity) Contains(t time.Time) bool {
	return !t.Before(v.NotBefore) && !t.After(v.NotAfter)
}

// Covers indicates whether the other validity is covered by this validity.
func (v Validity) Covers(other Validity) bool {
	return !other.NotBefore.Before(v.NotBefore) && !other.NotAfter.After(v.NotAfter)
}

// Validate checks that NotAfter is after NotBefore.
func (v Validity) Validate() error {
	if !v.NotAfter.After(v.NotBefore) {
		return ErrInvalidValidityPeriod
	}
	return nil
}

// IsZero indicates whether the validity period is zero.
func (v Validity) IsZero() bool {
	return v.NotBefore.IsZero() && v.NotAfter.IsZero()
}

func (v Validity) String() string {
	return fmt.Sprintf(
		"not_before=%s, not_after=%s",
		v.NotBefore.Format(time.RFC3339),
		v.NotAfter.Format(time.RFC3339),
	)
}
