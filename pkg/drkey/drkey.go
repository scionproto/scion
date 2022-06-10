// Copyright 2019 ETH Zurich
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

package drkey

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	pb "github.com/scionproto/scion/pkg/proto/drkey"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// Epoch represents a validity period.
type Epoch struct {
	cppki.Validity
}

// Equal returns true if both Epochs are identical.
func (e Epoch) Equal(other Epoch) bool {
	return e.NotBefore == other.NotBefore &&
		e.NotAfter == other.NotAfter
}

// NewEpoch constructs an Epoch from its uint32 encoded begin and end parts.
func NewEpoch(begin, end uint32) Epoch {
	return Epoch{
		cppki.Validity{
			NotBefore: util.SecsToTime(begin).UTC(),
			NotAfter:  util.SecsToTime(end).UTC(),
		},
	}
}

// Contains indicates whether the time point is inside this Epoch.
func (e *Epoch) Contains(t time.Time) bool {
	return e.Validity.Contains(t)
}

// Protocol is the 2-byte size protocol identifier
type Protocol uint16

// DRKey protocol types.
const (
	Generic = Protocol(pb.Protocol_PROTOCOL_GENERIC_UNSPECIFIED)
	SCMP    = Protocol(pb.Protocol_PROTOCOL_SCMP)
	DNS     = Protocol(pb.Protocol_PROTOCOL_DNS)
	COLIBRI = Protocol(pb.Protocol_PROTOCOL_COLIBRI)
)

func (p Protocol) String() string {
	name, ok := pb.Protocol_name[int32(p)]
	if !ok {
		return fmt.Sprintf("UNKNOWN(%d)", p)
	}
	return name
}

// IsPredefined checks whether this is a well-known, built-in protocol
// identifier, i.e. Generic, SCMP or DNS. Returns false for all other
// protocol identifiers ("niche protocols").
func (p Protocol) IsPredefined() bool {
	_, ok := pb.Protocol_name[int32(p)]
	return ok
}

func ProtocolStringToId(protocol string) (Protocol, bool) {
	id, ok := pb.Protocol_value[protocol]
	return Protocol(id), ok
}

// Key represents a raw binary key
type Key [16]byte

func (k Key) String() string {
	return "[redacted key]"
}

const drkeySalt = "Derive DRKey Key"

// SVMeta represents the information about a DRKey secret value.
type SVMeta struct {
	Validity time.Time
	ProtoId  Protocol
}

// SV represents a DRKey secret value.
type SV struct {
	Epoch   Epoch
	ProtoId Protocol
	Key     Key
}

// DeriveSV constructs a valid SV. asSecret is typically the AS master secret.
func DeriveSV(protoID Protocol, epoch Epoch, asSecret []byte) (SV, error) {
	msLen := len(asSecret)
	if msLen == 0 {
		return SV{}, serrors.New("Invalid zero sized secret")
	}

	totalLen := msLen + 18
	buf := make([]byte, totalLen)
	offset := 0
	binary.BigEndian.PutUint64(buf[:], uint64(msLen))
	offset += 8
	copy(buf[offset:], asSecret)
	offset += msLen
	binary.BigEndian.PutUint16(buf[offset:], uint16(protoID))
	offset += 2
	binary.BigEndian.PutUint32(buf[offset:], util.TimeToSecs(epoch.NotBefore))
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:], util.TimeToSecs(epoch.NotAfter))

	key := pbkdf2.Key(buf, []byte(drkeySalt), 1000, 16, sha256.New)
	sv := SV{
		Epoch:   epoch,
		ProtoId: protoID,
	}
	copy(sv.Key[:], key)
	return sv, nil
}

// / Lvl1Meta contains metadata to obtain a lvl1 key.
type Lvl1Meta struct {
	Validity     time.Time
	ProtoId      Protocol
	SrcIA, DstIA addr.IA
}

// Lvl1Key represents a level 1 DRKey.
type Lvl1Key struct {
	Epoch        Epoch
	ProtoId      Protocol
	SrcIA, DstIA addr.IA
	Key          Key
}

// ASHost represents the associated information for the ASHost key.
type ASHostMeta struct {
	ProtoId  Protocol
	Validity time.Time
	SrcIA    addr.IA
	DstIA    addr.IA
	DstHost  string
}

// ASHost represents a ASHost key.
type ASHostKey struct {
	ProtoId Protocol
	Epoch   Epoch
	SrcIA   addr.IA
	DstIA   addr.IA
	DstHost string
	Key     Key
}

// HostASMeta represents the associated information for the HostAS key.
type HostASMeta struct {
	ProtoId  Protocol
	Validity time.Time
	SrcIA    addr.IA
	DstIA    addr.IA
	SrcHost  string
}

// HostASKey represents a Host-AS key.
type HostASKey struct {
	ProtoId Protocol
	Epoch   Epoch
	SrcIA   addr.IA
	DstIA   addr.IA
	SrcHost string
	Key     Key
}

// HostHostMeta represents the associated information for the HostHostMeta key.
type HostHostMeta struct {
	ProtoId  Protocol
	Validity time.Time
	SrcIA    addr.IA
	DstIA    addr.IA
	SrcHost  string
	DstHost  string
}

// HostHostKey represents a Host-Host DRKey.
type HostHostKey struct {
	ProtoId Protocol
	Epoch   Epoch
	SrcIA   addr.IA
	DstIA   addr.IA
	SrcHost string
	DstHost string
	Key     Key
}
