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

package scrypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/util"
)

var (
	// ErrNotAfterNotSet indicates not_after is not set.
	ErrNotAfterNotSet = errors.New("not_after not set")
	// ErrNotBeforeNotSet indicates not_before is not set.
	ErrNotBeforeNotSet = errors.New("not_before not set")
	// ErrInvalidValidityPeriod indicates an invalid validity period.
	ErrInvalidValidityPeriod = errors.New("not_after before not_before")
)

// Validity indicates a validity period.
type Validity struct {
	NotBefore util.UnixTime `json:"not_before"`
	NotAfter  util.UnixTime `json:"not_after"`
}

// Contains indicates whether the provided time is inside the validity period.
func (v *Validity) Contains(t time.Time) bool {
	return !t.Before(v.NotBefore.Time) && !t.After(v.NotAfter.Time)
}

// Covers indicates whether the other validity is covered by this validity.
func (v *Validity) Covers(other Validity) bool {
	return !other.NotBefore.Before(v.NotBefore.Time) && !other.NotAfter.After(v.NotAfter.Time)
}

// Validate checks that NotAfter is after NotBefore.
func (v *Validity) Validate() error {
	if !v.NotAfter.After(v.NotBefore.Time) {
		return ErrInvalidValidityPeriod
	}
	return nil
}

// UnmarshalJSON checks that both NotBefore and NotAfter are set.
func (v *Validity) UnmarshalJSON(b []byte) error {
	var p validity
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return err
	}
	if err := p.checkAllSet(); err != nil {
		return err
	}
	*v = Validity{
		NotBefore: *p.NotBefore,
		NotAfter:  *p.NotAfter,
	}
	return nil
}

func (v *Validity) String() string {
	return fmt.Sprintf("[%s, %s]", util.TimeToCompact(v.NotBefore.Time),
		util.TimeToCompact(v.NotAfter.Time))
}

type validity struct {
	NotBefore *util.UnixTime `json:"not_before"`
	NotAfter  *util.UnixTime `json:"not_after"`
}

func (v *validity) checkAllSet() error {
	if v.NotBefore == nil {
		return ErrNotBeforeNotSet
	}
	if v.NotAfter == nil {
		return ErrNotAfterNotSet
	}
	return nil
}
