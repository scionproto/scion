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
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pierrec/lz4"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	MaxChainByteLength uint32 = 1 << 20
	// DefaultLeafCertValidity is the default validity time of a leaf certificate in seconds.
	DefaultLeafCertValidity = 3 * 24 * 60 * 60
	// DefaultIssuerCertValidity is the default validity time of an issuer certificate in seconds.
	DefaultIssuerCertValidity = 7 * 24 * 60 * 60

	// Error strings
	IssCertInvalid   = "Issuer certificate invalid"
	IssExpiresAfter  = "Issuer certificate expires after TRC"
	IssASNotFound    = "Issuing AS not found"
	LeafCertInvalid  = "Leaf certificate invalid"
	LeafExpiresAfter = "Leaf certificate expires after issuer certificate"
	LeafIssuedBefore = "Leaf certificate issued before issuer certificate"
)

type Key struct {
	IA  addr.IA
	Ver uint64
}

func NewKey(ia addr.IA, ver uint64) *Key {
	return &Key{IA: ia, Ver: ver}
}

func (k *Key) String() string {
	return fmt.Sprintf("%sv%d", k.IA, k.Ver)
}

// Chain contains two certificates, one for the leaf and one for the issuer. The leaf certificate
// is signed by the issuer certificate, which is signed by the TRC of the corresponding ISD.
type Chain struct {
	// Leaf is the leaf certificate of the chain. It is signed by the Issuer certificate.
	Leaf *Certificate `json:"0"`
	// Issuer is the issuer AS certificate of the chain. It is signed by the TRC of the ISD.
	Issuer *Certificate `json:"1"`
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

func ChainFromFile(path string, lz4_ bool) (*Chain, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ChainFromRaw(raw, lz4_)
}

// ChainFromDir reads all the {IA}-V*.crt (e.g., ISD1-ASff00_0_1-V17.crt) files
// contained directly in dir (no subdirectories), and out of those that match
// IA ia returns the newest one.  The chains must not be compressed. If an
// error occurs when parsing one of the files, f() is called with the error as
// argument. Execution continues with the remaining files.
//
// If no chain is found, the returned chain is nil and the error is set to nil.
func ChainFromDir(dir string, ia addr.IA, f func(err error)) (*Chain, error) {
	files, err := filepath.Glob(fmt.Sprintf("%s/%s-V*.crt", dir, ia.FileFmt(true)))
	if err != nil {
		return nil, err
	}
	var bestVersion uint64
	var bestChain *Chain
	for _, file := range files {
		chain, err := ChainFromFile(file, false)
		if err != nil {
			f(common.NewBasicError("Unable to read Chain file", err))
			continue
		}
		if !chain.Leaf.Subject.Eq(ia) {
			return nil, common.NewBasicError("IA mismatch", nil, "expected", ia,
				"found", chain.Leaf.Subject)
		}
		if chain.Leaf.Version > bestVersion {
			bestChain = chain
			bestVersion = chain.Leaf.Version
		}
	}
	return bestChain, nil
}

// ChainFromSlice creates a certificate chain from a list of certificates. The first certificate is
// the leaf certificate. The second certificate is the issuer certificate. Only chains with length
// of two are supported.
func ChainFromSlice(certs []*Certificate) (*Chain, error) {
	if len(certs) != 2 {
		return nil, common.NewBasicError("Unsupported chain length", nil, "len", len(certs))
	}
	if certs[0] == nil || certs[1] == nil {
		return nil, common.NewBasicError("Certificates must not be nil", nil, "leaf", certs[0],
			"iss", certs[1])
	}
	if !certs[0].Issuer.Eq(certs[1].Subject) {
		return nil, common.NewBasicError("Leaf not signed by issuer", nil, "expected",
			certs[0].Issuer, "actual", certs[1].Subject)
	}
	return &Chain{Leaf: certs[0], Issuer: certs[1]}, nil
}

func (c *Chain) Verify(subject addr.IA, t *trc.TRC) error {
	if c.Leaf.IssuingTime < c.Issuer.IssuingTime {
		return common.NewBasicError(LeafIssuedBefore, nil,
			"leaf", util.TimeToString(util.SecsToTime(c.Leaf.IssuingTime)),
			"issuer", util.TimeToString(util.SecsToTime(c.Issuer.IssuingTime)))
	}
	if c.Leaf.ExpirationTime > c.Issuer.ExpirationTime {
		return common.NewBasicError(LeafExpiresAfter, nil,
			"leaf", util.TimeToString(util.SecsToTime(c.Leaf.ExpirationTime)),
			"issuer", util.TimeToString(util.SecsToTime(c.Issuer.ExpirationTime)))
	}
	if !c.Issuer.CanIssue {
		return common.NewBasicError(IssCertInvalid, nil, "CanIssue", false)
	}
	if err := c.Leaf.Verify(subject, c.Issuer.SubjectSignKey, c.Issuer.SignAlgorithm); err != nil {
		return common.NewBasicError(LeafCertInvalid, err)
	}
	if c.Issuer.ExpirationTime > t.ExpirationTime {
		return common.NewBasicError(IssExpiresAfter, nil,
			"issuer", util.TimeToString(util.SecsToTime(c.Issuer.ExpirationTime)),
			"TRC", util.TimeToString(util.SecsToTime(t.ExpirationTime)))
	}
	coreAS, ok := t.CoreASes[c.Issuer.Issuer]
	if !ok {
		return common.NewBasicError(IssASNotFound, nil, "isdas", c.Issuer.Issuer, "coreASes",
			t.CoreASes)
	}
	if err := c.Issuer.Verify(c.Issuer.Issuer, coreAS.OnlineKey, coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError(IssCertInvalid, err)
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
	return &Chain{Issuer: c.Issuer.Copy(), Leaf: c.Leaf.Copy()}
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

func (c *Chain) UnmarshalJSON(b []byte) error {
	type Alias Chain
	var m map[string]interface{}
	err := json.Unmarshal(b, &m)
	if err != nil {
		return err
	}
	if err = validateFields(m, chainFields); err != nil {
		return common.NewBasicError(UnableValidateFields, err)
	}
	// XXX(roosd): Unmarshalling twice might affect performance.
	// After switching to go 1.10 we might make use of
	// https://golang.org/pkg/encoding/json/#Decoder.DisallowUnknownFields.
	return json.Unmarshal(b, (*Alias)(c))
}

func (c *Chain) Eq(o *Chain) bool {
	return c.Leaf.Eq(o.Leaf) && c.Issuer.Eq(o.Issuer)
}

func (c *Chain) IAVer() (addr.IA, uint64) {
	return c.Leaf.Subject, c.Leaf.Version
}

func (c *Chain) Key() *Key {
	return NewKey(c.Leaf.Subject, c.Leaf.Version)
}
