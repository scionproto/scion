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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"sort"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/crypto"
)

// Interface assertions
var _ fmt.Stringer = (*TRC)(nil)

var (
	fnTRC    = "testdata/ISD1-V0.trc"
	fnCACert = "testdata/CA1-1.crt"
)

func Test_TRCFromRaw(t *testing.T) {
	Convey("ChainFromRaw should parse bytes correctly", t, func() {
		trc, err := TRCFromRaw(loadRaw(fnTRC, t), false)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("CreationTime", trc.CreationTime, ShouldEqual, 1510146554)
		SoMsg("Description", trc.Description, ShouldEqual, "ISD 1")
		SoMsg("ExpirationTime", trc.ExpirationTime, ShouldEqual, 1541682554)
		SoMsg("GracePeriod", trc.GracePeriod, ShouldEqual, 18000)
		SoMsg("ISD", trc.ISD, ShouldEqual, 1)
		SoMsg("Quarantine", trc.Quarantine, ShouldBeFalse)
		SoMsg("QuorumCAs", trc.QuorumCAs, ShouldEqual, 3)
		SoMsg("QuorumTRC", trc.QuorumTRC, ShouldEqual, 2)
		SoMsg("ThresholdEEPKI", trc.ThresholdEEPKI, ShouldEqual, 2)
		SoMsg("Version", trc.Version, ShouldEqual, 0)

		Convey("CertLogs parsed correctly", func() {
			SoMsg("Log1", trc.CertLogs["Log1"], ShouldNotBeNil)
			SoMsg("Log2", trc.CertLogs["Log2"], ShouldNotBeNil)
			ip := net.ParseIP("127.0.0.75")
			SoMsg("Log1 addr", trc.CertLogs["Log1"].Addr, ShouldResemble,
				&Addr{IA: &addr.ISD_AS{I: 1, A: 11}, IP: ip})
			SoMsg("Log1 cert", trc.CertLogs["Log1"].Certificate, ShouldResemble,
				common.RawBytes{0xe3, 0x48, 0x78, 0xbc, 0xee, 0x40, 0x28, 0x71,
					0x87, 0x93, 0x72, 0x31, 0xa3, 0x7d, 0xaf, 0xcb, 0xf0, 0x07,
					0x76, 0xae, 0xe2, 0x3b, 0x77, 0x69, 0x71, 0x0c, 0x68, 0x34,
					0xf7, 0xf5, 0x17, 0x0e})
		})

		Convey("CoreASes parsed correctly", func() {
			SoMsg("1-11", trc.CoreASes[addr.ISD_AS{I: 1, A: 11}], ShouldNotBeNil)
			SoMsg("1-12", trc.CoreASes[addr.ISD_AS{I: 1, A: 12}], ShouldNotBeNil)
			SoMsg("1-13", trc.CoreASes[addr.ISD_AS{I: 1, A: 13}], ShouldNotBeNil)
			entry := &CoreAS{OfflineKeyAlg: crypto.Ed25519, OnlineKeyAlg: crypto.Ed25519}
			entry.OfflineKey = []byte{0x2b, 0x75, 0x84, 0xd7, 0xb4, 0x3d, 0xb3, 0xff,
				0x38, 0x76, 0x38, 0x9d, 0xd3, 0x44, 0x51, 0x12, 0x77, 0xba, 0x48,
				0x93, 0xd0, 0x0b, 0xb8, 0x29, 0x61, 0x20, 0x0b, 0x47, 0x69, 0xaf,
				0x3c, 0x58}
			entry.OnlineKey = []byte{0x26, 0xf8, 0x1a, 0x38, 0x34, 0xc6, 0x88, 0xef,
				0x38, 0x3b, 0x75, 0xdd, 0xa1, 0x4e, 0x27, 0x00, 0x55, 0x10, 0x3b,
				0x8d, 0xee, 0x4c, 0xf7, 0xc3, 0x70, 0xd5, 0x98, 0xf7, 0x0e, 0x42,
				0x91, 0xd4}

			SoMsg("CoreAS 1-11", trc.CoreASes[addr.ISD_AS{I: 1, A: 11}], ShouldResemble,
				entry)
		})

		Convey("RAINS parsed correctly", func() {
			SoMsg("OnlineKey", trc.RAINS.OnlineKey, ShouldResemble, common.RawBytes{0xc6,
				0xba, 0xca, 0x6e, 0x3f, 0xb5, 0x49, 0x54, 0x21, 0xbd, 0x4f, 0x02,
				0x7d, 0x6d, 0xbc, 0xc6, 0x41, 0xd9, 0xf5, 0x83, 0x05, 0x65, 0x1b,
				0x12, 0x31, 0xff, 0x7c, 0x51, 0xdc, 0x2b, 0xfa, 0xc1})
			SoMsg("OnlineKeyAlg", trc.RAINS.OnlineKeyAlg, ShouldResemble, crypto.Ed25519)
			SoMsg("RootRAINSKey", trc.RAINS.RootRAINSKey, ShouldResemble,
				common.RawBytes{0x23, 0xbe, 0x50, 0x51, 0x7d, 0x67, 0x7a, 0x71,
					0xfe, 0x2c, 0x18, 0x91, 0xe2, 0x50, 0x5e, 0x8f, 0x7f, 0x72,
					0x05, 0x7a, 0x67, 0x50, 0xb6, 0x6e, 0x4e, 0xb4, 0x7c, 0xc0,
					0x8b, 0xdc, 0x0c, 0x78})
			ip := net.ParseIP("127.0.0.107")
			SoMsg("TRCSrv", trc.RAINS.TRCSrv[0], ShouldResemble,
				&Addr{IA: &addr.ISD_AS{I: 1, A: 12}, IP: ip})
			SoMsg("TRCSrv size", len(trc.RAINS.TRCSrv), ShouldEqual, 3)
		})

		Convey("RootCAs parsed correctly", func() {
			SoMsg("CA1-1", trc.RootCAs["CA1-1"], ShouldNotBeNil)
			SoMsg("CA1-2", trc.RootCAs["CA1-2"], ShouldNotBeNil)
			SoMsg("CA1-3", trc.RootCAs["CA1-3"], ShouldNotBeNil)
			entry := &RootCA{OnlineKeyAlg: crypto.Ed25519}
			entry.ARPKIKey = []byte{0x20, 0x88, 0xbe, 0xac, 0xd2, 0xd7, 0xc7, 0x66,
				0x38, 0xe8, 0x7d, 0xf0, 0x16, 0x2b, 0x7c, 0x25, 0xda, 0x23, 0x3d,
				0xca, 0x8a, 0xea, 0x16, 0x9c, 0xd6, 0x24, 0x3e, 0x22, 0x9e, 0x1a,
				0x63, 0xdf}
			entry.Certificate = loadB64(fnCACert, t)
			entry.OnlineKey = []byte{0xb6, 0x2f, 0x12, 0xf6, 0xb9, 0x9c, 0xc8, 0x73,
				0xe0, 0xac, 0xe3, 0x97, 0x04, 0x67, 0x90, 0x86, 0x63, 0xcf, 0xdf,
				0x98, 0x15, 0xaa, 0x0f, 0x2f, 0x52, 0x53, 0x41, 0xb5, 0x55, 0x40,
				0x1f, 0xad}
			ipA := net.ParseIP("127.0.0.70")
			ipT := net.ParseIP("127.0.0.71")
			entry.ARPKISrv = []*Addr{{IA: &addr.ISD_AS{I: 1, A: 11}, IP: ipA}}
			entry.TRCSrv = []*Addr{{IA: &addr.ISD_AS{I: 1, A: 11}, IP: ipT}}
			SoMsg("RootCA CA1-1", trc.RootCAs["CA1-1"], ShouldResemble, entry)
		})

		Convey("Signatures parsed correctly", func() {
			SoMsg("1-11", trc.Signatures["1-11"], ShouldNotBeNil)
			SoMsg("1-12", trc.Signatures["1-12"], ShouldNotBeNil)
			SoMsg("1-13", trc.Signatures["1-13"], ShouldNotBeNil)
			SoMsg("Signature 1-11", trc.Signatures["1-11"], ShouldResemble,
				common.RawBytes{0x4e, 0x93, 0xab, 0x42, 0xfe, 0x37, 0xbe, 0x6a,
					0x4b, 0x7a, 0x14, 0xb0, 0xff, 0x33, 0xbd, 0x02, 0xe6, 0x5f,
					0xdd, 0x9f, 0xa9, 0xe6, 0x9b, 0x72, 0x43, 0x3a, 0x32, 0x3c,
					0xce, 0x4a, 0x7b, 0x8e, 0xcd, 0xdd, 0x6e, 0x3c, 0x16, 0xd5,
					0x1e, 0x79, 0xfa, 0xf7, 0xf5, 0x19, 0xd7, 0x51, 0x31, 0xdd,
					0xac, 0xaa, 0x2d, 0x37, 0xe9, 0x4d, 0x1f, 0x5a, 0x9d, 0x7c,
					0x3a, 0xda, 0x52, 0xc9, 0xf8, 0x0a})
		})

	})

	Convey("TRCFromRaw should avoid unpack bombs", t, func() {
		raw := []byte{0xFF, 0xFF, 0xFF, 0xFF}
		_, err := TRCFromRaw(raw, true)
		SoMsg("err", err, ShouldNotBeNil)
	})
}

type ISDAS []*addr.ISD_AS

func (i ISDAS) Len() int           { return len(i) }
func (i ISDAS) Swap(k, j int)      { i[k], i[j] = i[j], i[k] }
func (i ISDAS) Less(k, j int) bool { return i[k].I <= i[j].I && i[k].A < i[j].A }

func Test_TRC_CoreASList(t *testing.T) {
	Convey("CoreASList should return CoreASes correctly", t, func() {
		trc := loadTRC(fnTRC, t)
		list := trc.CoreASList()
		sort.Sort(ISDAS(list))
		SoMsg("CoreASList", list, ShouldResemble, []*addr.ISD_AS{{I: 1, A: 11},
			{I: 1, A: 12}, {I: 1, A: 13}})
	})
}

func Test_TRC_Sign(t *testing.T) {
	Convey("Sign should sign TRC correctly", t, func() {
		trc := loadTRC(fnTRC, t)
		packd, _ := trc.sigPack()
		err := crypto.Verify(packd, trc.Signatures["1-11"],
			trc.CoreASes[addr.ISD_AS{I: 1, A: 11}].OnlineKey, crypto.Ed25519)
		SoMsg("err", err, ShouldBeNil)
		key := []byte{0xaf, 0x00, 0x0e, 0xb6, 0x26, 0x4f, 0xbd, 0x20, 0xd1, 0x36, 0xed,
			0xae, 0x42, 0x65, 0xeb, 0x29, 0x15, 0x8e, 0xa6, 0x35, 0xef, 0x3d, 0x2a,
			0xac, 0xa2, 0xfd, 0x17, 0x2d, 0x4c, 0x42, 0x19, 0x5e, 0x26, 0xf8, 0x1a,
			0x38, 0x34, 0xc6, 0x88, 0xef, 0x38, 0x3b, 0x75, 0xdd, 0xa1, 0x4e, 0x27,
			0x00, 0x55, 0x10, 0x3b, 0x8d, 0xee, 0x4c, 0xf7, 0xc3, 0x70, 0xd5, 0x98,
			0xf7, 0x0e, 0x42, 0x91, 0xd4}
		orig := trc.Signatures["1-11"]
		_ = orig
		delete(trc.Signatures, "1-11")
		trc.Sign("1-11", key, crypto.Ed25519)
		SoMsg("Equal signature", trc.Signatures["1-11"], ShouldResemble, orig)
	})
}

func Test_TRC_CheckActive(t *testing.T) {
	Convey("Check active should report correctly", t, func() {
		t1 := loadTRC(fnTRC, t)
		t2 := loadTRC(fnTRC, t)
		t2.Version += 1

		t1.CreationTime = uint64(time.Now().Unix())
		t1.ExpirationTime = t1.CreationTime + 1<<20
		t2.CreationTime = uint64(time.Now().Unix())
		t2.ExpirationTime = t2.CreationTime + 1<<20

		Convey("TRC is active", func() {
			err := t1.CheckActive(t2)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("Early usage", func() {
			t1.CreationTime = uint64(time.Now().Unix()) + 1<<20
			err := t1.CheckActive(t2)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Late usage", func() {
			t1.ExpirationTime = uint64(time.Now().Unix()) - 1<<20
			err := t1.CheckActive(t2)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Outdated version", func() {
			t2.Version += 1
			err := t1.CheckActive(t2)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Grace period passed", func() {
			t2.CreationTime -= 1
			t2.GracePeriod = 0
			err := t1.CheckActive(t2)
			SoMsg("err", err, ShouldNotBeNil)
		})
	})
}

func Test_TRC_Compress(t *testing.T) {
	Convey("TRC is compressed correctly", t, func() {
		trc := loadTRC(fnTRC, t)
		comp, err := trc.Compress()
		SoMsg("err", err, ShouldBeNil)
		pTRC, _ := TRCFromRaw(comp, true)
		SoMsg("Compare", pTRC, ShouldResemble, trc)
	})
}

func Test_TRC_String(t *testing.T) {
	Convey("TRC is returned as String correctly", t, func() {
		trc := loadTRC(fnTRC, t)
		SoMsg("Compare", trc.String(), ShouldEqual, "TRC 1v0")

	})
}

func Test_TRC_JSON(t *testing.T) {
	Convey("TRC is returned as Json correctly", t, func() {
		trc := loadTRC(fnTRC, t)
		j, err := trc.JSON(false)
		SoMsg("err", err, ShouldEqual, nil)
		trcJ, err := TRCFromRaw(j, false)
		SoMsg("Eq", trc, ShouldResemble, trcJ)
	})
}

func Test_TRC_IsdVer(t *testing.T) {
	Convey("ISD version tuple is returned correctly", t, func() {
		trc := loadTRC(fnTRC, t)
		isd, ver := trc.IsdVer()
		SoMsg("IA", isd, ShouldEqual, 1)
		SoMsg("Ver", ver, ShouldEqual, 0)
	})
}

func Test_TRC_Key(t *testing.T) {
	Convey("Key is returned correctly", t, func() {
		trc := loadTRC(fnTRC, t)
		key := *trc.Key()
		SoMsg("Key", key, ShouldResemble, Key{ISD: 1, Ver: 0})
		SoMsg("String", (&key).String(), ShouldResemble, (&Key{ISD: 1, Ver: 0}).String())

	})
}

func loadTRC(filename string, t *testing.T) *TRC {
	trc, err := TRCFromRaw(loadRaw(filename, t), false)
	if err != nil {
		t.Fatalf("Error loading TRC from '%s': %v", filename, err)
	}
	return trc
}

func loadB64(filename string, t *testing.T) []byte {
	b, err := base64.StdEncoding.DecodeString(string(loadRaw(filename, t)))
	if err != nil {
		t.Fatalf("Unable to load base64 encoded string from '%s': %v", filename, err)
	}
	return b
}

func loadRaw(filename string, t *testing.T) []byte {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Unable to load raw from '%s': %v", filename, err)
	}
	return b
}
