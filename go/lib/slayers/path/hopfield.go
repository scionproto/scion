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

package path

import (
	"encoding/binary"
	"time"

	"github.com/scionproto/scion/go/lib/serrors"
)

const (
	// HopLen is the size of a HopField in bytes.
	HopLen = 12
	// MacLen is the size of the MAC of each HopField.
	MacLen = 6
)

// MaxTTL is the maximum age of a HopField in seconds.
const MaxTTL = 24 * 60 * 60 // One day in seconds

const expTimeUnit = MaxTTL / 256 // ~5m38s

// HopField is the HopField used in the SCION and OneHop path types.
//
// The Hop Field has the following format:
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |r r r r r r I E|    ExpTime    |           ConsIngress         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        ConsEgress             |                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//   |                              MAC                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type HopField struct {
	// IngressRouterAlert flag. If the IngressRouterAlert is set, the ingress router (in
	// construction direction) will process the L4 payload in the packet.
	IngressRouterAlert bool
	// EgressRouterAlert flag. If the EgressRouterAlert is set, the egress router (in
	// construction direction) will process the L4 payload in the packet.
	EgressRouterAlert bool
	// Exptime is the expiry time of a HopField. The field is 1-byte long, thus there are 256
	// different values available to express an expiration time. The expiration time expressed by
	// the value of this field is relative, and an absolute expiration time in seconds is computed
	// in combination with the timestamp field (from the corresponding info field) as follows
	//
	// Timestamp + (1 + ExpTime) * (24*60*60)/256
	ExpTime uint8
	// ConsIngress is the ingress interface ID in construction direction.
	ConsIngress uint16
	// ConsEgress is the egress interface ID in construction direction.
	ConsEgress uint16
	// Mac is the 6-byte Message Authentication Code to authenticate the HopField.
	Mac []byte
}

// DecodeFromBytes populates the fields from a raw buffer. The buffer must be of length >=
// path.HopLen
func (h *HopField) DecodeFromBytes(raw []byte) error {
	if len(raw) < HopLen {
		return serrors.New("HopField raw too short", "expected", HopLen, "actual", len(raw))
	}
	h.EgressRouterAlert = raw[0]&0x1 == 0x1
	h.IngressRouterAlert = raw[0]&0x2 == 0x2
	h.ExpTime = raw[1]
	h.ConsIngress = binary.BigEndian.Uint16(raw[2:4])
	h.ConsEgress = binary.BigEndian.Uint16(raw[4:6])
	h.Mac = append([]byte(nil), raw[6:6+MacLen]...)
	return nil
}

// SerializeTo writes the fields into the provided buffer. The buffer must be of length >=
// path.HopLen
func (h *HopField) SerializeTo(b []byte) error {
	if len(b) < HopLen {
		return serrors.New("buffer for HopField too short", "expected", MacLen, "actual", len(b))
	}
	b[0] = 0
	if h.EgressRouterAlert {
		b[0] |= 0x1
	}
	if h.IngressRouterAlert {
		b[0] |= 0x2
	}
	b[1] = h.ExpTime
	binary.BigEndian.PutUint16(b[2:4], h.ConsIngress)
	binary.BigEndian.PutUint16(b[4:6], h.ConsEgress)
	copy(b[6:12], h.Mac)

	return nil
}

// ExpTimeToDuration calculates the relative expiration time in seconds.
// Note that for a 0 value ExpTime, the minimal duration is expTimeUnit.
func ExpTimeToDuration(expTime uint8) time.Duration {
	return (time.Duration(expTime) + 1) * time.Duration(expTimeUnit) * time.Second
}
