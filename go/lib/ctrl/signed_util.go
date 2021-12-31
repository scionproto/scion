// Copyright 2018 ETH Zurich
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

package ctrl

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
)

const (
	// versionLen is the length of a the encoded scrypto.Version.
	versionLen = 8
	// prefixLen is the length of the IA, TRC base, and TRC serial of the
	// encoded X509SignSrc.
	prefixLen = addr.IABytes + 2*versionLen
)

// X509SignSrc identifes what x509 certificate can be used to verify the signature.
type X509SignSrc struct {
	IA           addr.IA
	Base         scrypto.Version
	Serial       scrypto.Version
	SubjectKeyID []byte
}

// NewX509SignSrc creates a X509SignSrc from a raw buffer.
func NewX509SignSrc(raw []byte) (X509SignSrc, error) {
	if len(raw) <= prefixLen {
		return X509SignSrc{}, serrors.New("buffer to small",
			"len", len(raw), "expected >", prefixLen)
	}
	src := X509SignSrc{
		IA:           addr.IAFromRaw(raw),
		Base:         scrypto.Version(binary.BigEndian.Uint64(raw[addr.IABytes:])),
		Serial:       scrypto.Version(binary.BigEndian.Uint64(raw[(addr.IABytes + versionLen):])),
		SubjectKeyID: append([]byte{}, raw[prefixLen:]...),
	}
	return src, nil
}

// IsZero indicates whether the source is equal to the zero value.
func (s X509SignSrc) IsZero() bool {
	return s.IA.IsZero() && s.Base == 0 && s.Serial == 0 && len(s.SubjectKeyID) == 0
}

// Equal indicates whether the contents of the two sources are the same.
func (s X509SignSrc) Equal(o X509SignSrc) bool {
	return s.IA.Equal(o.IA) &&
		s.Base == o.Base &&
		s.Serial == o.Serial &&
		bytes.Equal(s.SubjectKeyID, o.SubjectKeyID)
}

// Pack packs the source in a byte slice.
func (s X509SignSrc) Pack() []byte {
	buf := make([]byte, prefixLen+len(s.SubjectKeyID))
	s.IA.Write(buf)
	binary.BigEndian.PutUint64(buf[addr.IABytes:], uint64(s.Base))
	binary.BigEndian.PutUint64(buf[(addr.IABytes+versionLen):], uint64(s.Serial))
	copy(buf[prefixLen:], s.SubjectKeyID)
	return buf
}

func (s X509SignSrc) String() string {
	return fmt.Sprintf("ISD-AS: %s TRC: B%d-S%d SubjectKeyID: % X",
		s.IA, s.Base, s.Serial, s.SubjectKeyID)
}
