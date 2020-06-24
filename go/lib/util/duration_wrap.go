// Copyright 2018 Anapaya Systems
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

package util

import (
	"encoding"
	"flag"
	"time"
)

var _ (encoding.TextUnmarshaler) = (*DurWrap)(nil)
var _ (encoding.TextMarshaler) = DurWrap{}
var _ (flag.Value) = (*DurWrap)(nil)

// DurWrap is a wrapper to enable marshalling and unmarshalling of durations
// with the custom format.
type DurWrap struct {
	time.Duration
}

func (d *DurWrap) UnmarshalText(text []byte) error {
	return d.Set(string(text))
}

func (d *DurWrap) Set(text string) error {
	var err error
	d.Duration, err = ParseDuration(text)
	return err
}

func (d DurWrap) MarshalText() (text []byte, err error) {
	return []byte(FmtDuration(d.Duration)), nil
}

func (d DurWrap) String() string {
	return FmtDuration(d.Duration)
}
