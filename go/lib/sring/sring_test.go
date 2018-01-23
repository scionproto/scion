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

package sring

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	. "github.com/smartystreets/goconvey/convey"
)

type Op uint8

const (
	RES Op = iota
	WR
	RD
	REL
)

var testLabels = prometheus.Labels{"id": "test"}

func init() {
	InitMetrics("test")
}

func (o Op) String() string {
	switch o {
	case RES:
		return "RES"
	case WR:
		return "WR"
	case RD:
		return "RD"
	case REL:
		return "REL"
	}
	return "???"
}

type Command struct {
	op  Op
	arg int
}

func (c Command) String() string {
	return fmt.Sprintf("%v:%d", c.op, c.arg)
}

func runOps(script []Command) *SRing {
	var err error
	r := New(8, NewEntryBytes(128), "", testLabels)
	buffers := make(EntryList, 16)
	for _, cmd := range script {
		switch cmd.op {
		case RES:
			r.Reserve(buffers[:cmd.arg])
		case WR:
			_, err = r.Write(buffers[:cmd.arg])
		case RD:
			r.Read(buffers[:cmd.arg])
		case REL:
			_, err = r.Release(buffers[:cmd.arg])
		}
	}
	if err != nil {
		return nil
	}
	return r
}

func TestOperations(t *testing.T) {
	tests := []struct {
		script []Command
		expect [4]int
		fail   bool
	}{
		{[]Command{},
			[4]int{8, 8, 0, 0}, false},
		{[]Command{{RES, 6}},
			[4]int{2, 8, 0, 6}, false},
		{[]Command{{RES, 6}, {RES, 2}},
			[4]int{0, 8, 0, 8}, false},
		{[]Command{{RES, 6}, {WR, 2}, {RES, 2}, {WR, 4}},
			[4]int{0, 2, 6, 8}, false},
		{[]Command{{RES, 4}, {WR, 4}, {RD, 4}, {REL, 4}},
			[4]int{8, 8, 0, 0}, false},
		{[]Command{{RES, 4}, {WR, 1}, {WR, 1}, {RD, 2}, {WR, 2}, {REL, 2}, {RES, 6}},
			[4]int{0, 6, 2, 8}, false},
		{[]Command{{RES, 10}},
			[4]int{0, 8, 0, 8}, false},
		{[]Command{{REL, 2}},
			[4]int{0, 0, 0, 0}, true},
	}

	Convey("Test ops", t, func() {
		for _, test := range tests {
			Convey(fmt.Sprintf("%v", test.script), func() {
				r := runOps(test.script)
				if test.fail == false {
					SoMsg("Reservable", r.freeRefs.readable, ShouldEqual, test.expect[0])
					SoMsg("Writable", r.dataRefs.writable, ShouldEqual, test.expect[1])
					SoMsg("Readable", r.dataRefs.readable, ShouldEqual, test.expect[2])
					SoMsg("Releasable", r.freeRefs.writable, ShouldEqual, test.expect[3])
				} else {
					SoMsg("Error", r, ShouldBeNil)
				}
			})
		}
	})
}

func TestContents(t *testing.T) {
	r := New(8, NewEntryBytes(128), "", testLabels)
	data := []byte{1, 2, 3, 4, 5}
	buffersWriter := make(EntryList, 1)
	buffersReader := make(EntryList, 1)

	Convey("Test data transfer", t, func() {
		r.Reserve(buffersWriter)
		bufw := make([]byte, 8)
		copy(bufw, data)
		bufw = bufw[:len(data)]
		buffersWriter[0] = bufw
		r.Write(buffersWriter)

		r.Read(buffersReader)
		bufr := buffersReader[0].([]byte)[:cap(data)]
		SoMsg("Buffer contents", bufr, ShouldResemble, data)
		r.Release(buffersReader)
	})
}

// BenchmarkSRing1M sends 1Mil (1<<20) messages through an SRing.
func BenchmarkSRing1M(b *testing.B) {
	sr := New(1024, NewEntryBytes(1024), "", testLabels)
	wbuf := make(EntryList, 16)
	rbuf := make(EntryList, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			for total := 0; total != 1<<20; {
				want := min(1<<20-total, cap(wbuf))
				n := sr.Reserve(wbuf[:want])
				for k, buf := range wbuf[:n] {
					binary.LittleEndian.PutUint64(buf.([]byte), uint64(total+k))
				}
				sr.Write(wbuf[:n])
				total += n
			}
		}()
		for total := 0; total != 1<<20; {
			n := sr.Read(rbuf)
			for k, buf := range rbuf[:n] {
				val := int(binary.LittleEndian.Uint64(buf.([]byte)))
				if val != total+k {
					b.Logf("Expected %d Got %d", total+k, val)
					b.Fail()
				}
			}
			sr.Release(rbuf[:n])
			total += n
		}
	}
}
