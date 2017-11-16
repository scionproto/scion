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

package trc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/pierrec/lz4"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/crypto"
)

const MaxTRCByteLength uint32 = 1 << 20

type Key struct {
	ISD uint16
	Ver uint32
}

func NewKey(isd uint16, ver uint32) *Key {
	return &Key{ISD: isd, Ver: ver}
}

func (k *Key) String() string {
	return fmt.Sprintf("%dv%d", k.ISD, k.Ver)
}

type TRC struct {
	// CertLogs is a map from end-entity certificate logs to their addresses and public-key
	// certificate.
	CertLogs map[string]*CertLog
	// CoreASes is a map from core ASes to their online and offline key.
	CoreASes map[string]*CoreAS
	// CreationTime is the unix timestamp at which the TRC was created.
	CreationTime uint64
	// Description is an human-readable description of the ISD.
	Description string
	// ExpirationTime is the unix timestamp at which the TRC expires.
	ExpirationTime uint64
	// GracePeriod is the period during which the TRC is valid after creation of a new TRC in
	// seconds.
	GracePeriod uint64
	// ISD is the integer identifier from 1 to 4095.
	ISD uint16
	// Quarantine describes if the TRC is an early announcement (true) or valid (false).
	Quarantine bool
	// QuorumCAs is the quorum of root CAs required to change e RootCAs, CertLogs,
	// ThresholdEEPKI, and QuorumCAs.
	QuorumCAs uint32
	// QuorumTRC is the quorum of core ASes required to sign a new TRC.
	QuorumTRC uint32
	// Rains is the Rains entry.
	RAINS *Rains
	// RootCAs is a map from root CA names to their RootCA entry.
	RootCAs map[string]*RootCA
	// Signatures is a map from entity names to their signatures.
	Signatures map[string]common.RawBytes `json:",omitempty"`
	// ThresholdEEPKI is the threshold number of trusted parties (CAs and one log) required to
	// assert a domain’s policy.
	ThresholdEEPKI uint32
	// Version is the version number of the TRC
	Version uint32
}

func TRCFromRaw(raw common.RawBytes, lz4_ bool) (*TRC, error) {
	if lz4_ {
		// The python lz4 library uses lz4 block mode. To know the length of the
		// compressed block, it prepends the length of the original data as 4 bytes, little
		// endian, unsigned integer. We need to make sure that a malformed message does
		// not exhaust the available memory.
		bLen := binary.LittleEndian.Uint32(raw[:4])
		if bLen > MaxTRCByteLength {
			return nil, common.NewCError("TRC LZ4 block to large", "max",
				MaxTRCByteLength, "actual", bLen)
		}
		buf := make([]byte, bLen)
		n, err := lz4.UncompressBlock(raw[4:], buf, 0)
		if err != nil {
			return nil, err
		}
		raw = buf[:n]
	}
	t := &TRC{}
	if err := json.Unmarshal(raw, t); err != nil {
		return nil, err
	}
	return t, nil
}

// CoreASList returns a list of core ASes' addresses.
func (t *TRC) CoreASList() ([]*addr.ISD_AS, error) {
	l := make([]*addr.ISD_AS, 0, len(t.CoreASes))
	for key := range t.CoreASes {
		ia, err := addr.IAFromString(key)
		if err != nil {
			return nil, common.NewCError("Unable to parse core AS list", "err", err)
		}
		l = append(l, ia)
	}
	return l, nil
}

// Sign adds signature to the TRC. The signature is computed over the TRC without the signature map.
func (t *TRC) Sign(name string, signKey common.RawBytes, signAlgo string) error {
	sigInput, err := t.sigPack()
	if err != nil {
		return common.NewCError("Unable to create signature", "err", err)
	}
	sig, err := crypto.Sign(sigInput, signKey, signAlgo)
	if err != nil {
		return common.NewCError("Unable to create signature", "err", err)
	}
	t.Signatures[name] = sig
	return nil
}

// sigPack creates a sorted json object of all fields, except for the signature map.
func (t *TRC) sigPack() (common.RawBytes, error) {
	m := make(map[string]interface{})
	m["CertLogs"] = t.CertLogs
	m["CoreASes"] = t.CoreASes
	m["CreationTime"] = t.CreationTime
	m["Description"] = t.Description
	m["ExpirationTime"] = t.ExpirationTime
	m["GracePeriod"] = t.GracePeriod
	m["ISD"] = t.ISD
	m["Quarantine"] = t.Quarantine
	m["QuorumCAs"] = t.QuorumCAs
	m["QuorumTRC"] = t.QuorumTRC
	m["RAINS"] = t.RAINS
	m["RootCAs"] = t.RootCAs
	m["ThresholdEEPKI"] = t.ThresholdEEPKI
	m["Version"] = t.Version
	sigInput, err := json.Marshal(m)
	if err != nil {
		return nil, common.NewCError("TRC: Unable to create signature input", "err", err)
	}
	return sigInput, nil
}

// CheckActive checks if TRC is active and can be used for certificate chain verification. MaxTRC is
// the newest active TRC of the same ISD which we know of.
func (t *TRC) CheckActive(maxTRC *TRC) error {
	currTime := uint64(time.Now().Unix())
	if currTime < t.CreationTime {
		return common.NewCError("TRC Creation time in the future", "now",
			timeToString(currTime), "creation", timeToString(t.CreationTime))
	} else if currTime > t.ExpirationTime {
		return common.NewCError("TRC expired", "now", timeToString(currTime), "expiration",
			timeToString(t.ExpirationTime))
	} else if t.Version == maxTRC.Version {
		return nil
	} else if t.Version+1 != maxTRC.Version {
		return common.NewCError("Inactive TRC version", "expected", fmt.Sprintf("%d or %d",
			maxTRC.Version-1, maxTRC.Version), "actual", t.Version)
	} else if currTime > maxTRC.CreationTime+maxTRC.GracePeriod {
		return common.NewCError("TRC grace period has passed", "now", timeToString(currTime),
			"expiration", timeToString(maxTRC.CreationTime+maxTRC.GracePeriod))
	}
	return nil
}

// Verify checks the validity of the TRC based on a trusted TRC. The trusted TRC can either be
// the direct predecessor TRC or a cross signing TRC.
func (t *TRC) Verify(trust *TRC) error {
	if t.ISD == trust.ISD {
		return t.verifyUpdate(trust)
	}
	return t.verifyXSig(trust)
}

// verifyUpdate checks the validity of a updated TRC.
func (t *TRC) verifyUpdate(old *TRC) error {
	if old.ISD != t.ISD {
		return common.NewCError("Invalid TRC ISD", "expected", old.ISD, "actual", t.ISD)
	}
	if old.Version+1 != t.Version {
		return common.NewCError("Invalid TRC version", "expected",
			old.Version+1, "actual", t.Version)
	}
	if t.CreationTime < old.CreationTime+old.GracePeriod {
		return common.NewCError("Invalid TRC creation time", "expected >",
			timeToString(old.CreationTime+old.GracePeriod), "actual",
			timeToString(t.CreationTime))
	}
	if t.Quarantine || old.Quarantine {
		return common.NewCError("Early announcement")
	}
	return t.verifySignatures(old)
}

// verifySignatures checks the signatures of the updated TRC.
func (t *TRC) verifySignatures(old *TRC) error {
	sigInput, err := t.sigPack()
	if err != nil {
		return err
	}
	var valCount uint32 = 0
	// Only verify signatures which are from core ASes defined in old TRC
	for signer, coreAS := range old.CoreASes {
		sig, ok := t.Signatures[signer]
		if !ok {
			log.Info("Signature from past CoreAS not present", "AS", signer)
			continue
		}
		err = crypto.Verify(sigInput, sig, coreAS.OnlineKey, coreAS.OnlineKeyAlg)
		if err == nil {
			valCount++
		}
	}
	if valCount < old.QuorumTRC {
		return common.NewCError("Not enough valid signatures",
			"expected", old.QuorumTRC, "actual", valCount)
	}
	return nil
}

// verifyXSig checks the cross signatures of the updated TRC.
func (t *TRC) verifyXSig(trust *TRC) error {
	// FIXME(roosd): implement cross signatures
	return nil
}

// Compress compresses the JSON generated from the TRC using lz4 block mode and
// prepends the original length (4 bytes, little endian, unsigned). This is necessary, since
// the python lz4 library expects this format.
func (t *TRC) Compress() (common.RawBytes, error) {
	raw, err := json.Marshal(t)
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

func (t *TRC) String() string {
	return fmt.Sprintf("TRC %dv%d", t.ISD, t.Version)
}

func (t *TRC) JSON(indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(t, "", strings.Repeat(" ", 4))
	}
	return json.Marshal(t)
}

func (t *TRC) IsdVer() (uint16, uint32) {
	return t.ISD, t.Version
}

func (t *TRC) Key() *Key {
	return NewKey(t.ISD, t.Version)
}

func timeToString(t uint64) string {
	return time.Unix(int64(t), 0).UTC().Format(common.TimeFmt)
}
