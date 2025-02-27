// Copyright 2022 ETH Zurich
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

// DRKey protocol types.
const (
	Generic = Protocol(pb.Protocol_PROTOCOL_GENERIC_UNSPECIFIED)
	SCMP    = Protocol(pb.Protocol_PROTOCOL_SCMP)
)

// Epoch represents a validity period.
type Epoch = cppki.Validity

// NewEpoch constructs an Epoch from its uint32 encoded begin and end parts.
func NewEpoch(begin, end uint32) Epoch {
	return Epoch{
		NotBefore: util.SecsToTime(begin),
		NotAfter:  util.SecsToTime(end),
	}
}

// Protocol is the 2-byte size protocol identifier
type Protocol uint16

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

// SecretValueMeta represents the information about a DRKey secret value.
type SecretValueMeta struct {
	Validity time.Time
	ProtoId  Protocol
}

// SecretValue represents a DRKey secret value.
type SecretValue struct {
	Epoch   Epoch
	ProtoId Protocol
	Key     Key
}

// DeriveSV constructs a valid SV. asSecret is typically the AS master secret.
func DeriveSV(protoID Protocol, epoch Epoch, asSecret []byte) (SecretValue, error) {
	msLen := len(asSecret)
	if msLen == 0 {
		return SecretValue{}, serrors.New("Invalid zero sized secret")
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
	sv := SecretValue{
		Epoch:   epoch,
		ProtoId: protoID,
	}
	copy(sv.Key[:], key)
	return sv, nil
}

// / Level1Meta contains metadata to obtain a Level1 key.
type Level1Meta struct {
	Validity     time.Time
	ProtoId      Protocol
	SrcIA, DstIA addr.IA
}

// Level1Key represents a level 1 DRKey.
type Level1Key struct {
	Epoch        Epoch
	ProtoId      Protocol
	SrcIA, DstIA addr.IA
	Key          Key
}

// ASHostMeta represents the associated information for the ASHost key.
type ASHostMeta struct {
	ProtoId  Protocol
	Validity time.Time
	SrcIA    addr.IA
	DstIA    addr.IA
	DstHost  string
}

// ASHostKey represents a ASHost key.
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
