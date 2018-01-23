// Copyright 2017 ETH Zurich
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

// Go implementation of the certificate.
// To create JSON strings, either json.Marshal or json.MarshalIndent

package cert

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pierrec/lz4"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	MaxChainByteLength uint32 = 1 << 20
	// LeafValidity is the default validity time of a leaf certificate in seconds.
	DefaultLeafCertValidity = 3 * 24 * 60 * 60
	// CoreValidity is the default validity time of a core certificate in seconds.
	DefaultCoreCertValidity = 7 * 24 * 60 * 60

	// Error strings
	CoreCertInvalid  = "Core certificate invalid"
	CoreExpiresAfter = "Core certificate expires after TRC"
	IssASNotFound    = "Issuing Core AS not found"
	LeafCertInvalid  = "Leaf certificate invalid"
	LeafExpiresAfter = "Leaf certificate expires after core certificate"
	LeafIssuedBefore = "Leaf certificate issued before core certificate"
)

type Key struct {
	IA  addr.ISD_AS
	Ver uint64
}

func NewKey(ia *addr.ISD_AS, ver uint64) *Key {
	return &Key{IA: *ia, Ver: ver}
}

func (k *Key) String() string {
	return fmt.Sprintf("%sv%d", k.IA, k.Ver)
}

// Chain contains two certificates, one fore the leaf and one for the core. The leaf certificate
// is signed by the core certificate, which is signed by the TRC of the corresponding ISD.
type Chain struct {
	// Leaf is the leaf certificate of the chain. It is signed by the Core certificate.
	Leaf *Certificate `json:"0"`
	// Core is the core AS certificate of the chain. It is signed by the TRC of the ISD.
	Core *Certificate `json:"1"`
}

func ChainFromRaw(raw common.RawBytes, lz4_ bool) (*Chain, error) {
	if lz4_ {
		// The python lz4 library uses lz4 block mode. To know the length of the
		// compressed block, it prepends the length of the original data as 4 bytes, little
		// endian, unsigned integer. We need to make sure that a malformed message does
		// not exhaust the available memory.
		byteLen := binary.LittleEndian.Uint32(raw[:4])
		if byteLen > MaxChainByteLength {
			return nil, common.NewBasicError("Certificate chain LZ4 block too large", nil,
				"max", MaxChainByteLength, "actual", byteLen)
		}
		buf := make([]byte, byteLen)
		n, err := lz4.UncompressBlock(raw[4:], buf, 0)
		if err != nil {
			return nil, err
		}
		raw = buf[:n]
	}
	c := &Chain{}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Chain) Verify(subject *addr.ISD_AS, t *trc.TRC) error {
	if c.Leaf.IssuingTime < c.Core.IssuingTime {
		return common.NewBasicError(LeafIssuedBefore, nil, "leaf",
			util.TimeToString(c.Leaf.IssuingTime), "core",
			util.TimeToString(c.Core.IssuingTime))
	}
	if c.Leaf.ExpirationTime > c.Core.ExpirationTime {
		return common.NewBasicError(LeafExpiresAfter, nil, "leaf",
			util.TimeToString(c.Leaf.ExpirationTime), "core",
			util.TimeToString(c.Core.ExpirationTime))
	}
	if !c.Core.CanIssue {
		return common.NewBasicError(CoreCertInvalid, nil, "CanIssue", false)
	}
	if err := c.Leaf.Verify(subject, c.Core.SubjectSignKey, c.Core.SignAlgorithm); err != nil {
		return common.NewBasicError(LeafCertInvalid, err)
	}
	if c.Core.ExpirationTime > t.ExpirationTime {
		return common.NewBasicError(CoreExpiresAfter, nil, "core",
			util.TimeToString(c.Core.ExpirationTime), "TRC",
			util.TimeToString(t.ExpirationTime))
	}
	coreAS, ok := t.CoreASes[*c.Core.Issuer]
	if !ok {
		return common.NewBasicError(IssASNotFound, nil, "isdas", c.Core.Issuer, "coreASes",
			t.CoreASes)
	}
	if err := c.Core.Verify(c.Core.Issuer, coreAS.OnlineKey, coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError(CoreCertInvalid, err)
	}
	return nil
}

// Compress compresses the JSON generated from the certificate chain using lz4 block mode and
// prepends the original length (4 bytes, little endian, unsigned). This is necessary, since
// the python lz4 library expects this format.
func (c *Chain) Compress() (common.RawBytes, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	comp := make([]byte, lz4.CompressBlockBound(len(raw))+4)
	binary.LittleEndian.PutUint32(comp[:4], uint32(len(raw)))
	n, err := lz4.CompressBlock(raw, comp[4:], 0)
	if err != nil {
		return nil, err
	}
	return comp[:n+4], err
}

func (c *Chain) Copy() *Chain {
	return &Chain{Core: c.Core.Copy(), Leaf: c.Leaf.Copy()}
}

func (c *Chain) String() string {
	return fmt.Sprintf("CertificateChain %sv%d", c.Leaf.Subject, c.Leaf.Version)
}

func (c *Chain) JSON(indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(c, "", strings.Repeat(" ", 4))
	}
	return json.Marshal(c)
}

func (c *Chain) Eq(o *Chain) bool {
	return c.Leaf.Eq(o.Leaf) && c.Core.Eq(o.Core)
}

func (c *Chain) IAVer() (*addr.ISD_AS, uint64) {
	return c.Leaf.Subject, c.Leaf.Version
}

func (c *Chain) Key() *Key {
	return NewKey(c.Leaf.Subject, c.Leaf.Version)
}
