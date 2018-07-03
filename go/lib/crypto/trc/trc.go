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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/pierrec/lz4"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	MaxTRCByteLength uint32 = 1 << 20

	// Error strings
	EarlyUsage          = "Creation time in the future"
	EarlyAnnouncement   = "Early announcement"
	Expired             = "TRC expired"
	GracePeriodPassed   = "TRC grace period has passed"
	InactiveVersion     = "Inactive TRC version"
	InvalidCreationTime = "Invalid TRC creation time"
	InvalidISD          = "Invalid TRC ISD"
	InvalidQuorum       = "Not enough valid signatures"
	InvalidVersion      = "Invalid TRC version"
	ReservedVersion     = "Invalid version 0"
	SignatureMissing    = "Signature missing"
	UnableSigPack       = "TRC: Unable to create signature input"
)

type Key struct {
	ISD addr.ISD
	Ver uint64
}

func NewKey(isd addr.ISD, ver uint64) *Key {
	return &Key{ISD: isd, Ver: ver}
}

func (k *Key) String() string {
	return fmt.Sprintf("%dv%d", k.ISD, k.Ver)
}

// TRCVerResult is the result of verifying core AS signatures.
type TRCVerResult struct {
	Quorum   uint32
	Verified []addr.IA
	Failed   map[addr.IA]error
}

func (tvr *TRCVerResult) QuorumOk() bool {
	return uint32(len(tvr.Verified)) >= tvr.Quorum
}

type TRC struct {
	// CertLogs is a map from end-entity certificate logs to their addresses and public-key
	// certificate.
	CertLogs map[string]*CertLog
	// CoreASes is a map from core ASes to their online and offline key.
	CoreASes map[addr.IA]*CoreAS
	// CreationTime is the unix timestamp in seconds at which the TRC was created.
	CreationTime uint32
	// Description is an human-readable description of the ISD.
	Description string
	// ExpirationTime is the unix timestamp in seconds at which the TRC expires.
	ExpirationTime uint32
	// GracePeriod is the period during which the TRC is valid after creation of a new TRC in
	// seconds.
	GracePeriod uint32
	// ISD is the integer identifier from 1 to 4095.
	ISD addr.ISD
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
	// Version is the version number of the TRC. The value 0 is reserved and shall not be used.
	Version uint64
}

func TRCFromRaw(raw common.RawBytes, lz4_ bool) (*TRC, error) {
	if lz4_ {
		// The python lz4 library uses lz4 block mode. To know the length of the
		// compressed block, it prepends the length of the original data as 4 bytes, little
		// endian, unsigned integer. We need to make sure that a malformed message does
		// not exhaust the available memory.
		bLen := binary.LittleEndian.Uint32(raw[:4])
		if bLen > MaxTRCByteLength {
			return nil, common.NewBasicError("TRC LZ4 block too large", nil,
				"max", MaxTRCByteLength, "actual", bLen)
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
	if t.Version == 0 {
		return nil, common.NewBasicError(ReservedVersion, nil)
	}
	return t, nil
}

func TRCFromFile(path string, lz4_ bool) (*TRC, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return TRCFromRaw(raw, lz4_)
}

// TRCFromDir reads all the *.trc files contained directly in dir (no
// subdirectories), and out of those that match ISD isd returns the newest one.
// The TRCs must not be compressed. If an error occurs when parsing one of the
// files, f() is called with the error as argument. Execution continues with
// the remaining files.
//
// If no TRC is found, the returned TRC is nil and the error is set to nil.
func TRCFromDir(dir string, isd addr.ISD, f func(err error)) (*TRC, error) {
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var bestVersion uint64
	var bestTRC *TRC
	for _, info := range infos {
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".trc") {
			trcObj, err := TRCFromFile(filepath.Join(dir, info.Name()), false)
			if err != nil {
				f(common.NewBasicError("Unable to read TRC file", err))
				continue
			}
			fileISD, version := trcObj.IsdVer()
			if fileISD == isd && version > bestVersion {
				bestTRC = trcObj
				bestVersion = version
			}
		}
	}
	return bestTRC, nil
}

func (t *TRC) IsdVer() (addr.ISD, uint64) {
	return t.ISD, t.Version
}

func (t *TRC) Key() *Key {
	return NewKey(t.ISD, t.Version)
}

// CoreASList returns a list of core ASes' addresses.
func (t *TRC) CoreASList() []addr.IA {
	l := make([]addr.IA, 0, len(t.CoreASes))
	for key := range t.CoreASes {
		l = append(l, key)
	}
	return l
}

// CheckActive checks if TRC is active and can be used for certificate chain verification. MaxTRC is
// the newest active TRC of the same ISD which we know of.
func (t *TRC) CheckActive(maxTRC *TRC) error {
	if t.Quarantine {
		return common.NewBasicError(EarlyAnnouncement, nil)
	}
	currTime := uint32(time.Now().Unix())
	if currTime < t.CreationTime {
		return common.NewBasicError(EarlyUsage, nil,
			"now", timeToString(currTime), "creation", timeToString(t.CreationTime))
	} else if currTime > t.ExpirationTime {
		return common.NewBasicError(Expired, nil,
			"now", timeToString(currTime), "expiration", timeToString(t.ExpirationTime))
	} else if t.Version == maxTRC.Version {
		return nil
	} else if t.Version+1 != maxTRC.Version {
		return common.NewBasicError(
			InactiveVersion, nil,
			"expected", fmt.Sprintf("%d or %d", maxTRC.Version-1, maxTRC.Version),
			"actual", t.Version,
		)
	} else if currTime > maxTRC.CreationTime+maxTRC.GracePeriod {
		return common.NewBasicError(GracePeriodPassed, nil, "now", timeToString(currTime),
			"expiration", timeToString(maxTRC.CreationTime+maxTRC.GracePeriod))
	}
	return nil
}

// Sign adds signature to the TRC. The signature is computed over the TRC without the signature map.
func (t *TRC) Sign(name string, signKey common.RawBytes, signAlgo string) error {
	sigInput, err := t.sigPack()
	if err != nil {
		return common.NewBasicError("Unable to pack TRC for signing", err)
	}
	sig, err := crypto.Sign(sigInput, signKey, signAlgo)
	if err != nil {
		return common.NewBasicError("Unable to create signature", err)
	}
	t.Signatures[name] = sig
	return nil
}

// Verify checks the validity of the TRC based on a trusted TRC. The trusted TRC can either be
// the direct predecessor TRC or a cross signing TRC.
func (t *TRC) Verify(trust *TRC) (*TRCVerResult, error) {
	if t.ISD == trust.ISD {
		return t.verifyUpdate(trust)
	}
	return nil, t.verifyXSig(trust)
}

// verifyUpdate checks the validity of a updated TRC.
func (t *TRC) verifyUpdate(old *TRC) (*TRCVerResult, error) {
	if old.ISD != t.ISD {
		return nil, common.NewBasicError(InvalidISD, nil, "expected", old.ISD, "actual", t.ISD)
	}
	if old.Version+1 != t.Version {
		return nil, common.NewBasicError(InvalidVersion, nil,
			"expected", old.Version+1, "actual", t.Version)
	}
	if t.CreationTime < old.CreationTime+old.GracePeriod {
		return nil, common.NewBasicError(
			InvalidCreationTime, nil,
			"expected >", timeToString(old.CreationTime+old.GracePeriod),
			"actual", timeToString(t.CreationTime),
		)
	}
	if t.Quarantine || old.Quarantine {
		return nil, common.NewBasicError(EarlyAnnouncement, nil)
	}
	return t.verifySignatures(old)
}

// verifySignatures checks the signatures of the updated TRC.
func (t *TRC) verifySignatures(old *TRC) (*TRCVerResult, error) {
	sigInput, err := t.sigPack()
	if err != nil {
		return nil, err
	}
	var tvr = &TRCVerResult{}
	// Only verify signatures which are from core ASes defined in old TRC
	for signer, coreAS := range old.CoreASes {
		sig, ok := t.Signatures[signer.String()]
		if !ok {
			tvr.Failed[signer] = common.NewBasicError(SignatureMissing, nil, "as", signer)
			continue
		}
		err = crypto.Verify(sigInput, sig, coreAS.OnlineKey, coreAS.OnlineKeyAlg)
		if err == nil {
			tvr.Verified = append(tvr.Verified, signer)
		} else {
			tvr.Failed[signer] = err
		}
	}
	if !tvr.QuorumOk() {
		return tvr, common.NewBasicError(InvalidQuorum, nil,
			"expected", old.QuorumTRC, "actual", len(tvr.Verified))
	}
	return tvr, nil
}

// verifyXSig checks the cross signatures of the updated TRC.
func (t *TRC) verifyXSig(trust *TRC) error {
	// FIXME(roosd): implement cross signatures
	return nil
}

// sigPack creates a sorted json object of all fields, except for the signature map.
func (t *TRC) sigPack() (common.RawBytes, error) {
	if t.Version == 0 {
		return nil, common.NewBasicError(ReservedVersion, nil)
	}
	m := make(map[string]interface{})
	m["CertLogs"] = t.CertLogs
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
	m["CoreASes"] = t.CoreASes
	sigInput, err := json.Marshal(m)
	if err != nil {
		return nil, common.NewBasicError(UnableSigPack, err)
	}
	return sigInput, nil
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

func (t *TRC) JSON(indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(t, "", strings.Repeat(" ", 4))
	}
	return json.Marshal(t)
}

// JSONEquals checks if two TRCs are the same based on their JSON
// serializations.
func (t *TRC) JSONEquals(other *TRC) (bool, error) {
	tj, err := t.JSON(false)
	if err != nil {
		return false, common.NewBasicError("Unable to build JSON", err)
	}
	oj, err := other.JSON(false)
	if err != nil {
		return false, common.NewBasicError("Unable to build JSON", err)
	}
	return bytes.Compare(tj, oj) == 0, nil
}

func (t *TRC) String() string {
	return fmt.Sprintf("TRC %dv%d", t.ISD, t.Version)
}

func timeToString(t uint32) string {
	return util.TimeToString(util.USecsToTime(t))
}
