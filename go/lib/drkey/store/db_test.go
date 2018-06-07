// Copyright 2018 ETH Zurich
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

package store

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	timeOffset = 10 * time.Minute
)

var (
	rawSecret = []byte("0123456789012345")
	rawSrcIA  = []byte{0xF0, 0x11, 0xF2, 0x33, 0x44, 0x55, 0x66, 0x77}
	rawDstIA  = []byte{0xF0, 0x11, 0xF2, 0x33, 0x44, 0x55, 0x66, 0x88}
	rawAddIA  = []byte{0xF0, 0x11, 0xF2, 0x33, 0x44, 0x55, 0x66, 0x99}
	SrcHostIP = net.IPv4(192, 168, 1, 37)
	DstHostIP = net.IPv4(192, 168, 1, 38)
	AddHostIP = net.IPv4(192, 168, 1, 39)
)

func TestDRKeyLvl1(t *testing.T) {
	Convey("Initialize DB and derive DRKey", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		expTime := util.TimeToSecs(time.Now().Add(timeOffset))
		sv := &drkey.DRKeySV{ExpTime: expTime}
		SoMsg("drkey", sv, ShouldNotBeNil)
		err := sv.SetKey(rawSecret, common.RawBytes(time.Now().Format("01-02-2016")))
		SoMsg("drkey", err, ShouldBeNil)
		drkeyLvl1 := &drkey.DRKeyLvl1{
			SrcIa:   addr.IAFromRaw(rawSrcIA),
			DstIa:   addr.IAFromRaw(rawDstIA),
			ExpTime: expTime,
		}
		SoMsg("drkey", drkeyLvl1, ShouldNotBeNil)
		err = drkeyLvl1.SetKey(sv.Key)
		SoMsg("drkey", err, ShouldBeNil)
		Convey("Insert drkey into database", func() {
			rows, err := db.InsertDRKeyLvl1(drkeyLvl1, expTime)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldBeGreaterThan, 0)
			rows, err = db.InsertDRKeyLvl1(drkeyLvl1, expTime)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Fetch drkey from database", func() {
				newKey, err := db.GetDRKeyLvl1(drkeyLvl1, util.TimeToSecs(time.Now()))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("drkey", newKey, ShouldResemble, drkeyLvl1.Key)
			})

			Convey("Remove outdated drkeys", func() {
				db.RemoveOutdatedDRKeyLvl1(util.TimeToSecs(time.Now().Add(-timeOffset)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldEqual, 0)
				rows, err = db.RemoveOutdatedDRKeyLvl1(util.TimeToSecs(time.Now().Add(2 * timeOffset)))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("rows", rows, ShouldBeGreaterThan, 0)
			})
		})
	})
}

func TestDRKeyLvl2(t *testing.T) {
	Convey("Initialize DB and derive DRKey", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		srcIa := addr.IAFromRaw(rawSrcIA)
		dstIa := addr.IAFromRaw(rawDstIA)
		expTime := util.TimeToSecs(time.Now().Add(timeOffset))
		drkeyLvl1 := &drkey.DRKeyLvl1{
			SrcIa:   srcIa,
			DstIa:   dstIa,
			ExpTime: expTime,
			Key:     rawSecret,
		}
		SoMsg("drkey", drkeyLvl1, ShouldNotBeNil)
		drkeyLvl2 := &drkey.DRKeyLvl2{
			Proto:   "test",
			Type:    drkey.AS2AS,
			SrcIa:   srcIa,
			DstIa:   dstIa,
			AddIa:   addr.IAFromRaw(rawAddIA),
			SrcHost: addr.HostFromIP(SrcHostIP),
			DstHost: addr.HostFromIP(DstHostIP),
			AddHost: addr.HostFromIP(AddHostIP),
			ExpTime: expTime,
		}
		SoMsg("drkey", drkeyLvl2, ShouldNotBeNil)
		err := drkeyLvl2.SetKey(drkeyLvl1.Key)
		SoMsg("drkey", err, ShouldBeNil)
		Convey("Insert drkey into database", func() {
			rows, err := db.InsertDRKeyLvl2(drkeyLvl2, expTime)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldBeGreaterThan, 0)
			rows, err = db.InsertDRKeyLvl2(drkeyLvl2, expTime)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Fetch drkey from database", func() {
				newKey, err := db.GetDRKeyLvl2(drkeyLvl2, util.TimeToSecs(time.Now()))
				SoMsg("err", err, ShouldBeNil)
				SoMsg("drkey", newKey, ShouldResemble, drkeyLvl2.Key)
			})
		})
	})
}

func newDatabase(t *testing.T) (*DB, func()) {
	file, err := ioutil.TempFile("", "db-test-")
	if err != nil {
		t.Fatalf("unable to create temp file")
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		t.Fatalf("unable to close temp file")
	}
	db, err := New(name)
	if err != nil {
		t.Fatalf("unable to initialize database")
	}
	return db, func() {
		db.Close()
		os.Remove(name)
	}
}
