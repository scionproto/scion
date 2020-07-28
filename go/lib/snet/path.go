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

package snet

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
)

// Path is an abstract representation of a path. Most applications do not need
// access to the raw internals.
//
// An empty path is a special kind of path that can be used for intra-AS
// traffic. Empty paths are valid return values for certain route calls (e.g.,
// if the source and destination ASes match, or if a router was configured
// without a source of paths). An empty path only contains a Destination value,
// all other values are zero values.
type Path interface {
	// UnderlayNextHop returns the address:port pair of a local-AS underlay
	// speaker. Usually, this is a border router that will forward the traffic.
	UnderlayNextHop() *net.UDPAddr
	// Path returns a raw (data-plane compatible) representation of the path.
	// The returned path is initialized and ready for use in snet calls that
	// deal with raw paths.
	Path() *spath.Path
	// Interfaces returns a list of interfaces on the path. If the list is not
	// available the result is nil.
	Interfaces() []PathInterface
	// Destination is the AS the path points to. Empty paths return the local
	// AS of the router that created them.
	Destination() addr.IA
	// Metadata returns supplementary information about this path.
	// Returns nil if the metadata is not available.
	Metadata() PathMetadata
	// Copy create a copy of the path.
	Copy() Path
}

// PathInterface is an interface of the path. This is currently an interface so
// that packages which can not depend on snet can still implement the snet.Path
// interface.
type PathInterface interface {
	// ID is the ID of the interface.
	ID() common.IFIDType
	// IA is the ISD AS identifier of the interface.
	IA() addr.IA
}

// PathMetadata contains supplementary information about a path.
type PathMetadata interface {
	// MTU returns the MTU of the path.
	MTU() uint16
	// Expiry returns the expiration time of the path.
	Expiry() time.Time
}

type PathFingerprint string

func (pf PathFingerprint) String() string {
	return common.RawBytes(pf).String()
}

// Fingerprint uniquely identifies the path based on the sequence of
// ASes and BRs, i.e. by its PathInterfaces.
// Other metadata, such as MTU or NextHop have no effect on the fingerprint.
// Returns empty string for paths where the interfaces list is not available.
func Fingerprint(path Path) PathFingerprint {
	interfaces := path.Interfaces()
	if len(interfaces) == 0 {
		return ""
	}
	h := sha256.New()
	for _, intf := range interfaces {
		binary.Write(h, binary.BigEndian, intf.IA().IAInt())
		binary.Write(h, binary.BigEndian, intf.ID())
	}
	return PathFingerprint(h.Sum(nil))
}

// partialPath is a path object with incomplete metadata. It is used as a
// temporary solution where a full path cannot be reconstituted from other
// objects, notably snet.UDPAddr and snet.SVCAddr.
type partialPath struct {
	spath       *spath.Path
	underlay    *net.UDPAddr
	destination addr.IA
}

func (p *partialPath) UnderlayNextHop() *net.UDPAddr {
	return p.underlay
}

func (p *partialPath) Path() *spath.Path {
	if p.spath == nil {
		return nil
	}
	return p.spath.Copy()
}

func (p *partialPath) Interfaces() []PathInterface {
	return nil
}

func (p *partialPath) Destination() addr.IA {
	return p.destination
}

func (p *partialPath) Metadata() PathMetadata {
	return nil
}

func (p *partialPath) Copy() Path {
	if p == nil {
		return nil
	}
	return &partialPath{
		spath:       p.spath.Copy(),
		underlay:    CopyUDPAddr(p.underlay),
		destination: p.destination,
	}
}

func (p *partialPath) String() string {
	return fmt.Sprintf("{spath: %s, underlay: %s, dest: %s}", p.spath, p.underlay, p.destination)
}
