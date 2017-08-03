package pring

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

type Op uint8

const (
	RES Op = iota
	WR
	RD
	REL
)

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
	r := New(8, 128)
	buffers := make([][]byte, 16)
	for _, cmd := range script {
		switch cmd.op {
		case RES:
			_, err = r.Reserve(buffers[:cmd.arg])
		case WR:
			_, err = r.Write(buffers[:cmd.arg])
		case RD:
			_, err = r.Read(buffers[:cmd.arg])
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
			[4]int{8, 0, 0, 0}, false},
		{[]Command{{RES, 6}},
			[4]int{2, 6, 0, 0}, false},
		{[]Command{{RES, 6}, {RES, 2}},
			[4]int{0, 8, 0, 0}, false},
		{[]Command{{RES, 6}, {WR, 2}, {RES, 2}, {WR, 4}},
			[4]int{0, 2, 6, 0}, false},
		{[]Command{{RES, 4}, {WR, 4}, {RD, 4}, {REL, 4}},
			[4]int{8, 0, 0, 0}, false},
		{[]Command{{RES, 4}, {WR, 1}, {WR, 1}, {RD, 2}, {WR, 2}, {REL, 2}, {RES, 6}},
			[4]int{0, 6, 2, 0}, false},
		{[]Command{{RES, 10}},
			[4]int{0, 8, 0, 0}, false},
		{[]Command{{WR, 2}},
			[4]int{0, 0, 0, 0}, true},
		{[]Command{{REL, 2}},
			[4]int{0, 0, 0, 0}, true},
	}

	Convey("Test ops", t, func() {
		for _, test := range tests {
			Convey(fmt.Sprintf("%v", test.script), func() {
				r := runOps(test.script)
				if test.fail == false {
					SoMsg("Reservable", r.reservable, ShouldEqual, test.expect[0])
					SoMsg("Writable", r.writable, ShouldEqual, test.expect[1])
					SoMsg("Readable", r.readable, ShouldEqual, test.expect[2])
					SoMsg("Releasable", r.releasable, ShouldEqual, test.expect[3])
				} else {
					SoMsg("Error", r, ShouldBeNil)
				}
			})
		}
	})
}

func TestContents(t *testing.T) {
	r := New(8, 128)
	data := []byte{1, 2, 3, 4, 5}
	buffersWriter := make([][]byte, 1)
	buffersReader := make([][]byte, 1)

	Convey("Test data transfer", t, func() {
		r.Reserve(buffersWriter)
		copy(buffersWriter[0], data)
		buffersWriter[0] = buffersWriter[0][:len(data)]
		r.Write(buffersWriter)

		r.Read(buffersReader)
		buffersReader[0] = buffersReader[0][:cap(data)]
		SoMsg("Buffer contents", buffersReader[0], ShouldResemble, data)
		r.Release(buffersReader)
	})
}
