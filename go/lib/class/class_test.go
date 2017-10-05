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

package class

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/smartystreets/goconvey/convey"
)

type TestCase struct {
	hpktKey  string
	hpkt     *ClsPkt
	classKey string
	class    *Class
	expected bool
}

func TestClassMap(t *testing.T) {
	Convey("Create class map", t, func() {
		cm := NewClassMap()
		Convey("Add element classA", func() {
			classA := NewClass("classA", nil)
			err := cm.Add(classA)
			SoMsg("err", err, ShouldBeNil)

			Convey("Retrieve classA should return the class", func() {
				class, err := cm.Get("classA")
				SoMsg("err", err, ShouldBeNil)
				SoMsg("class", class, ShouldResemble, classA)
			})

			Convey("Retrieve classB should return error", func() {
				_, err := cm.Get("classB")
				SoMsg("err", err, ShouldNotBeNil)
			})

			Convey("Add classA again should return error", func() {
				err := cm.Add(NewClass("classA", nil))
				SoMsg("err", err, ShouldNotBeNil)
			})

			Convey("Remove classB should return error", func() {
				err := cm.Remove("classB")
				SoMsg("err", err, ShouldNotBeNil)
			})

			Convey("Remove classA should work", func() {
				err := cm.Remove("classA")
				SoMsg("err", err, ShouldBeNil)
			})
		})
	})
}

func TestBasicConds(t *testing.T) {
	Convey("Conditions", t, func() {
		Convey("Any returns correct values on Eval", func() {
			c := NewCondAnyOf()
			SoMsg("empty any", c.Eval(nil), ShouldBeTrue)
			c = NewCondAnyOf(CondTrue)
			SoMsg("true", c.Eval(nil), ShouldBeTrue)
			c = NewCondAnyOf(CondFalse, CondFalse)
			SoMsg("false, false", c.Eval(nil), ShouldBeFalse)
			c = NewCondAnyOf(CondFalse, CondTrue, CondFalse)
			SoMsg("false, true, false", c.Eval(nil), ShouldBeTrue)
		})

		Convey("All returns correct values on Eval", func() {
			c := NewCondAllOf()
			SoMsg("empty all", c.Eval(nil), ShouldBeTrue)
			c = NewCondAllOf(CondTrue)
			SoMsg("true", c.Eval(nil), ShouldBeTrue)
			c = NewCondAllOf(CondFalse, CondFalse)
			SoMsg("false, false", c.Eval(nil), ShouldBeFalse)
			c = NewCondAllOf(CondFalse, CondTrue, CondFalse)
			SoMsg("false, true, false", c.Eval(nil), ShouldBeFalse)
		})

		Convey("Mixed conds return correct values on Eval", func() {
			c := NewCondAllOf(
				NewCondAnyOf(),
				NewCondAllOf(),
				CondTrue,
			)
			SoMsg("All(Any(), All(), true)", c.Eval(nil), ShouldBeTrue)
			c = NewCondAllOf(
				NewCondAnyOf(),
				NewCondAllOf(),
				CondFalse,
			)
			SoMsg("All(Any(), All(), false)", c.Eval(nil), ShouldBeFalse)
			c = NewCondAllOf(
				CondTrue,
				CondTrue,
				NewCondAnyOf(
					CondFalse,
					CondFalse,
					NewCondAllOf(),
				),
			)
			SoMsg("All(true, true, Any(false, false, All()))", c.Eval(nil), ShouldBeTrue)
		})
	})

}

func TestIPv4Conds(t *testing.T) {
	tcs := InitTestCases()

	Convey("Evaluate classes for different packets", t, func() {
		for _, tc := range tcs {
			Convey(fmt.Sprintf("class=%s, hpkt=%s", tc.classKey, tc.hpktKey), func() {
				SoMsg("eval", tc.class.Eval(tc.hpkt), ShouldEqual, tc.expected)
			})
		}
	})
}

func InitTestCases() []*TestCase {
	tests := []struct {
		class    string
		hpkt     string
		expected bool
	}{
		{"ClassA", "192.168.1.1->192.168.1.2", true},
		{"ClassA", "192.168.1.1->10.0.0.2", true},
		{"ClassB", "192.168.1.1->192.168.1.2", false},
		{"ClassB", "192.168.1.1->10.0.0.2", true},
		{"ClassC", "192.168.1.1->192.168.1.2", false},
		{"ClassC", "192.168.1.1->10.0.0.2", false},
		{"ClassA", "", false}, // Force nil hpkt
	}

	var tcs []*TestCase
	hpkts := InitHPkts()
	classes := InitClasses()
	for _, test := range tests {
		tcs = append(tcs, &TestCase{
			hpktKey:  test.hpkt,
			hpkt:     hpkts[test.hpkt],
			classKey: test.class,
			class:    classes[test.class],
			expected: test.expected,
		})
	}
	return tcs
}

func InitHPkts() map[string]*ClsPkt {
	pkts := make(map[string]*ClsPkt)
	pkts["192.168.1.1->192.168.1.2"] = InitHPkt(
		&layers.IPv4{
			SrcIP: net.IP{192, 168, 1, 1},
			DstIP: net.IP{192, 168, 1, 2},
		},
		[]byte{1, 1, 1, 1},
	)
	pkts["192.168.1.1->10.0.0.2"] = InitHPkt(
		&layers.IPv4{
			SrcIP: net.IP{192, 168, 1, 1},
			DstIP: net.IP{10, 0, 0, 2},
		},
		[]byte{2, 2, 2, 2},
	)
	return pkts
}

func InitHPkt(ipv4 *layers.IPv4, pld []byte) *ClsPkt {
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{},
		ipv4,
		gopacket.Payload(pld),
	)
	return NewClsPkt(buf.Bytes())
}

func InitClasses() map[string]*Class {
	return map[string]*Class{
		"ClassA": NewClass(
			"ClassA",
			NewCondAllOf(
				NewCondIPv4(
					&IPv4MatchSource{
						&net.IPNet{
							net.IP{192, 168, 1, 0},
							net.IPv4Mask(255, 255, 255, 240),
						},
					},
				),
			),
		),
		"ClassB": NewClass(
			"ClassB",
			NewCondAllOf(
				NewCondIPv4(
					&IPv4MatchDestination{
						&net.IPNet{
							net.IP{10, 0, 0, 0},
							net.IPv4Mask(255, 0, 0, 0),
						},
					},
				),
			),
		),
		"ClassC": NewClass(
			"ClassC",
			NewCondAllOf(
				NewCondIPv4(
					&IPv4MatchToS{
						TOS: 0x80,
					},
				),
				NewCondIPv4(
					&IPv4MatchSource{
						&net.IPNet{
							net.IP{192, 168, 1, 1},
							net.IPv4Mask(255, 255, 255, 255),
						},
					},
				),
			),
		),
	}
}
