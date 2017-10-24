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

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

const MaxChainByteLength uint32 = 1 << 20

type Key struct {
	IA  addr.ISD_AS
	Ver int
}

func (k *Key) String() string {
	return fmt.Sprintf("%s.%d", k.IA, k.Ver)
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
		// endian, unsigned integer. We need to make sure, that a malformed message does
		// not exhaust the available memory.
		byteLen := binary.LittleEndian.Uint32(raw[:4])
		if byteLen > MaxChainByteLength {
			return nil, common.NewCError("Exceeding byte length", "max",
				MaxChainByteLength, "actual", byteLen)
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

func (c *Chain) Verify(subject *addr.ISD_AS, trc interface{}) error {
	if err := c.Leaf.Verify(subject, c.Core.SubjectSigKey, c.Core.SignAlgorithm); err != nil {
		return err
	}
	// Fixme(roosd): Verify Core Certificate based on TRC
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

func (c *Chain) IAVer() (*addr.ISD_AS, int) {
	return c.Leaf.Subject, c.Leaf.Version
}

func (c *Chain) Key() *Key {
	return &Key{IA: *c.Leaf.Subject, Ver: c.Leaf.Version}
}
