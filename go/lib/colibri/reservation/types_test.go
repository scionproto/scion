// Copyright 2019 ETH Zurich, Anapaya Systems
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

package reservation

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSegmentIDFromRaw(t *testing.T) {
	raw := xtest.MustParseHexString("ffaa00001101facecafe")
	id, err := SegmentIDFromRaw(raw)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	refASID := xtest.MustParseAS("ffaa:0:1101")
	if id.ASID != refASID {
		t.Fatalf("Bad ASID. Got %x expected %x", id.ASID, refASID)
	}
	refSuffix := xtest.MustParseHexString("facecafe")
	if bytes.Compare(id.Suffix[:], refSuffix) != 0 {
		t.Fatalf("Bad Suffix. Got %s expected %s",
			hex.EncodeToString(id.Suffix[:]), hex.EncodeToString(refSuffix))
	}
}

func TestSegmentIDRead(t *testing.T) {
	reference := SegmentID{
		ASID: xtest.MustParseAS("ffaa:0:1101"),
	}
	copy(reference.Suffix[:], xtest.MustParseHexString("facecafe"))
	raw := make([]byte, SegmentIDLen)
	n, err := reference.Read(raw)
	if err != nil {
		t.Fatalf("Unexpect error: %v", err)
	}
	if n != SegmentIDLen {
		t.Fatalf("Unexpected read size %d. Expected %d", n, SegmentIDLen)
	}
	rawReference := xtest.MustParseHexString("ffaa00001101facecafe")
	if bytes.Compare(raw, rawReference) != 0 {
		t.Fatalf("Serialized SegmentID is different: %s expected %s",
			hex.EncodeToString(raw), hex.EncodeToString(rawReference))
	}
}

func TestE2EIDFromRaw(t *testing.T) {
	raw := xtest.MustParseHexString("ffaa00001101facecafedeadbeeff00d")
	id, err := E2EIDFromRaw(raw)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	refASID := xtest.MustParseAS("ffaa:0:1101")
	if id.ASID != refASID {
		t.Fatalf("Bad ASID. Got %x expected %x", id.ASID, refASID)
	}
	refSuffix := xtest.MustParseHexString("facecafedeadbeeff00d")
	if bytes.Compare(id.Suffix[:], refSuffix) != 0 {
		t.Fatalf("Bad Suffix. Got %s expected %s",
			hex.EncodeToString(id.Suffix[:]), hex.EncodeToString(refSuffix))
	}
}

func TestE2EIDRead(t *testing.T) {
	reference := E2EID{
		ASID: xtest.MustParseAS("ffaa:0:1101"),
	}
	copy(reference.Suffix[:], xtest.MustParseHexString("facecafedeadbeeff00d"))
	raw := make([]byte, E2EIDLen)
	n, err := reference.Read(raw)
	if err != nil {
		t.Fatalf("Unexpect error: %v", err)
	}
	if n != E2EIDLen {
		t.Fatalf("Unexpected read size %d. Expected %d", n, E2EIDLen)
	}
	rawReference := xtest.MustParseHexString("ffaa00001101facecafedeadbeeff00d")
	if bytes.Compare(raw, rawReference) != 0 {
		t.Fatalf("Serialized E2EID is different: %s expected %s",
			hex.EncodeToString(raw), hex.EncodeToString(rawReference))
	}
}

func TestTickFromTime(t *testing.T) {
	if tick := TickFromTime(time.Unix(0, 0)); tick != 0 {
		t.Fatalf("Wrong tick %v, expected 0", tick)
	}
	if tick := TickFromTime(time.Unix(3, 999999)); tick != 0 {
		t.Fatalf("Wrong tick %v, expected 0", tick)
	}
	if tick := TickFromTime(time.Unix(4, 0)); tick != 1 {
		t.Fatalf("Wrong tick %v, expected 0", tick)
	}
}

func TestValidateBWCls(t *testing.T) {
	for i := 0; i < 64; i++ {
		c := BWCls(i)
		if err := c.Validate(); err != nil {
			t.Fatalf("Unexpected error at i = %d: %v", i, err)
		}
	}
	c := BWCls(64)
	if err := c.Validate(); err == nil {
		t.Fatalf("Expected validation error but did not get one")
	}
}

func TestValidateRLC(t *testing.T) {
	for i := 0; i < 64; i++ {
		c := RLC(i)
		if err := c.Validate(); err != nil {
			t.Fatalf("Unexpected error at i = %d: %v", i, err)
		}
	}
	c := RLC(64)
	if err := c.Validate(); err == nil {
		t.Fatalf("Expected validation error but did not get one")
	}
}

func TestValidateIndex(t *testing.T) {
	for i := 0; i < 16; i++ {
		idx := Index(i)
		if err := idx.Validate(); err != nil {
			t.Fatalf("Unexpected error at i = %d: %v", i, err)
		}
	}
	idx := Index(16)
	if err := idx.Validate(); err == nil {
		t.Fatal("Expected validation error but did not get one")
	}
}

func TestValidatePathType(t *testing.T) {
	validTypes := []PathType{
		DownPath,
		UpPath,
		PeeringDownPath,
		PeeringUpPath,
		E2EPath,
		CorePath,
	}
	for _, vt := range validTypes {
		pt := PathType(vt)
		if err := pt.Validate(); err != nil {
			t.Fatalf("Unexpected error with type %v: %v", vt, err)
		}
	}
	pt := PathType(UnknownPath)
	if err := pt.Validate(); err == nil {
		t.Fatalf("Expected validation error but did not get one")
	}
	pt = PathType(CorePath + 1)
	if err := pt.Validate(); err == nil {
		t.Fatalf("Expected validation error but did not get one")
	}
}

func TestValidateInfoField(t *testing.T) {
	infoField := InfoField{
		ExpirationTick: 0,
		BWCls:          0,
		RLC:            0,
		Idx:            0,
		PathType:       CorePath,
	}
	if err := infoField.Validate(); err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
	otherIF := infoField
	otherIF.BWCls = 64
	if err := otherIF.Validate(); err == nil {
		t.Fatalf("Expected validation error but did not get one")
	}
	otherIF = infoField
	otherIF.RLC = 64
	if err := otherIF.Validate(); err == nil {
		t.Fatalf("Expected validation error but did not get one")
	}
	otherIF = infoField
	otherIF.Idx = 16
	if err := otherIF.Validate(); err == nil {
		t.Fatalf("Expected validation error but did not get one")
	}
	otherIF = infoField
	otherIF.PathType = CorePath + 1
	if err := otherIF.Validate(); err == nil {
		t.Fatalf("Expected validation error but did not get one")
	}
}

var rawReference = xtest.MustParseHexString("16ebdb4f0d042500")
var reference = InfoField{
	ExpirationTick: 384555855,
	BWCls:          13,
	RLC:            4,
	Idx:            2,
	PathType:       E2EPath,
}

func TestInfoFieldFromRaw(t *testing.T) {
	info, err := InfoFieldFromRaw(rawReference)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if info.ExpirationTick != reference.ExpirationTick {
		t.Fatalf("Bad ExpirationTick %v != %v", info.ExpirationTick, reference.ExpirationTick)
	}
	if info.BWCls != reference.BWCls {
		t.Fatalf("Bad BWCls %v != %v", info.BWCls, reference.BWCls)
	}
	if info.RLC != reference.RLC {
		t.Fatalf("Bad RLC %v != %v", info.RLC, reference.RLC)
	}
	if info.Idx != reference.Idx {
		t.Fatalf("Bad Idx %v != %v", info.Idx, reference.Idx)
	}
	if info.PathType != reference.PathType {
		t.Fatalf("Bad PathType %v != %v", info.PathType, reference.PathType)
	}
}

func TestInfoFieldRead(t *testing.T) {
	raw := make([]byte, InfoFieldLen)
	// pollute the buffer with garbage
	for i := 0; i < InfoFieldLen; i++ {
		raw[i] = byte(i % 256)
	}
	n, err := reference.Read(raw)
	if err != nil {
		t.Fatalf("Unexpect error: %v", err)
	}
	if n != InfoFieldLen {
		t.Fatalf("Unexpected read size %d. Expected %d", n, InfoFieldLen)
	}

	if bytes.Compare(raw, rawReference) != 0 {
		t.Fatalf("Fail to serialize InfoField. %v != %v",
			hex.EncodeToString(raw), hex.EncodeToString(rawReference))
	}
}
