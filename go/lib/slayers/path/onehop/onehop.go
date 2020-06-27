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

package onehop

import (
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
)

// PathLen is the length of a serialized one hop path in bytes
const PathLen = path.InfoLen + 2*path.HopLen

// Path encodes a one hop path. A one hop path is a special path that is created by a SCION router
// in the first AS and completed by a SCION router in the second AS. It is used during beaconing
// when there is not yet any other path segment available.
type Path struct {
	Info      path.InfoField
	FirstHop  path.HopField
	SecondHop path.HopField
}

func (o *Path) DecodeFromBytes(data []byte) error {
	if len(data) < PathLen {
		return serrors.New("buffer too short for OneHop path", "expected", PathLen, "actual",
			len(data))
	}
	offset := 0
	if err := o.Info.DecodeFromBytes(data[:path.InfoLen]); err != nil {
		return err
	}
	offset += path.InfoLen
	if err := o.FirstHop.DecodeFromBytes(data[offset : offset+path.HopLen]); err != nil {
		return err
	}
	offset += path.HopLen
	return o.SecondHop.DecodeFromBytes(data[offset : offset+path.HopLen])
}

func (o *Path) SerializeTo(b []byte) error {
	if len(b) < PathLen {
		return serrors.New("buffer too short for OneHop path", "expected", PathLen, "actual",
			len(b))
	}
	offset := 0
	if err := o.Info.SerializeTo(b[:offset+path.InfoLen]); err != nil {
		return err
	}
	offset += path.InfoLen
	if err := o.FirstHop.SerializeTo(b[offset : offset+path.HopLen]); err != nil {
		return err
	}
	offset += path.HopLen
	return o.SecondHop.SerializeTo(b[offset : offset+path.HopLen])
}

func (o *Path) Reverse() error {
	return serrors.New("OneHop path cannot be reversed")
}

func (o *Path) Len() int {
	return PathLen
}
