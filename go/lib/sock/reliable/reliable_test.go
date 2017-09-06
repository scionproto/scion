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

package reliable

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

type ExitData struct {
	value []byte
	err   error
}

type TestCase struct {
	msg       string
	ia        addr.ISD_AS
	dst       AppAddr
	want      []byte
	timeoutOK bool
}

func Server(x chan ExitData, tc TestCase, sockName string, client func()) {
	os.Remove(sockName)
	defer os.Remove(sockName)
	listener, err := Listen(sockName)
	if err != nil {
		x <- ExitData{err: err}
		return
	}

	client()

	conn, err := listener.Accept()
	if err != nil {
		x <- ExitData{err: err}
		return
	}

	buf := make([]byte, len(tc.want))
	_, err = io.ReadFull(conn.UnixConn, buf)
	if err != nil {
		x <- ExitData{err: err}
		return
	}

	err = conn.Close()
	if err != nil {
		x <- ExitData{err: err}
		return
	}
	x <- ExitData{value: buf}
}

func Client(x chan ExitData, tc TestCase, sockName string) {
	conn, err := Dial(sockName)
	if err != nil {
		x <- ExitData{err: err}
		return
	}

	_, err = conn.WriteTo([]byte(tc.msg), tc.dst)
	if err != nil {
		x <- ExitData{err: err}
		return
	}

	// Do not close the connection or the server might not have time
	// to get the data out
	x <- ExitData{}
}

func ClientRegister(x chan ExitData, tc TestCase, sockName string) {
	// The below returns with error because the server never replies before
	// closing the connection, but we're not interested in testing this
	// behavior
	Register(sockName, &tc.ia, tc.dst)
	x <- ExitData{}
}

func TestWriteTo(t *testing.T) {
	nilAddr := addr.HostNone{}
	testCases := []TestCase{
		{msg: "", dst: AppAddr{Addr: nilAddr, Port: 0},
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 0}},
		{msg: "test", dst: AppAddr{Addr: nilAddr, Port: 0},
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 4, 't', 'e', 's', 't'}},
		{msg: "foo", dst: AppAddr{Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)), Port: 80},
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 3,
				127, 0, 0, 1, 0, 80, 'f', 'o', 'o'}},
		{msg: "bar", dst: AppAddr{Addr: addr.HostFromIP(net.IPv6loopback), Port: 80},
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 3,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				0, 80, 'b', 'a', 'r'}}}

	Convey("Client sending message to Server using WriteTo", t, func() {
		Convey("Server should receive correct raw messages", func() {
			for i, tc := range testCases {
				Convey(fmt.Sprintf("Client sent message \"%v\"", tc.msg), func() {
					sockName := getRandFile()

					sc := make(chan ExitData, 1)
					cc := make(chan ExitData, 1)
					go Server(sc, tc, sockName, func() {
						go Client(cc, tc, sockName)
					})

					var sData ExitData
					select {
					case sData = <-sc:
					case <-time.After(3 * time.Second):
						sData = ExitData{nil, common.NewCError("Server timed out")}
					}
					var cData ExitData
					select {
					case cData = <-cc:
					case <-time.After(3 * time.Second):
						cData = ExitData{nil, common.NewCError("Client timed out")}
					}

					prefix := fmt.Sprintf("WriteTo %d", i)
					SoMsg(prefix+" server error", sData.err, ShouldBeNil)
					SoMsg(prefix+" client error", cData.err, ShouldBeNil)
					SoMsg(prefix+" server data", sData.value, ShouldResemble, tc.want)
				})
			}
		})
	})
}

func TestRegister(t *testing.T) {
	nilAddr := addr.HostNone{}

	testCases := []TestCase{
		{ia: addr.ISD_AS{I: 1, A: 10}, dst: AppAddr{Addr: nilAddr, Port: 0},
			want: nil, timeoutOK: true},
		{ia: addr.ISD_AS{I: 2, A: 21},
			dst: AppAddr{Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)), Port: 80},
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 13,
				3, 17, 0, 32, 0, 21, 0, 80, 1, 127, 0, 0, 1}, timeoutOK: false},
		{ia: addr.ISD_AS{I: 2, A: 21},
			dst: AppAddr{Addr: addr.HostFromIP(net.IPv6loopback), Port: 80},
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 25,
				3, 17, 0, 32, 0, 21, 0, 80, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, timeoutOK: false}}

	Convey("Client registering to SCIOND", t, func() {
		Convey("SCIOND should receive correct raw messages", func() {
			for i, tc := range testCases {
				Convey(fmt.Sprintf("Client registered to %v, %v", tc.ia, tc.dst), func() {
					sockName := getRandFile()

					sc := make(chan ExitData, 1)
					cc := make(chan ExitData, 1)
					go Server(sc, tc, sockName, func() {
						go ClientRegister(cc, tc, sockName)
					})

					var sData ExitData
					select {
					case sData = <-sc:
					case <-time.After(3 * time.Second):
						if !tc.timeoutOK {
							sData = ExitData{nil, common.NewCError("Server timed out")}
						}
					}
					var cData ExitData
					select {
					case cData = <-cc:
					case <-time.After(3 * time.Second):
						cData = ExitData{nil, common.NewCError("Client timed out")}
					}

					prefix := fmt.Sprintf("Register %d", i)
					SoMsg(prefix+" server error", sData.err, ShouldBeNil)
					SoMsg(prefix+" client error", cData.err, ShouldBeNil)
					SoMsg(prefix+" server data", sData.value, ShouldResemble, tc.want)
				})
			}
		})
	})
}

type SetupFunc func() interface{}
type EndpointFunc func(*Conn, interface{})
type TestFunc func(t *testing.T, expected interface{}, have interface{}) bool

func setupFunc() interface{} {
	return make([]byte, 1280)
}

func readFunc(conn *Conn, data interface{}) {
	buffer := data.([]byte)
	for j := 0; j < 1000; j++ {
		_, err := conn.Read(buffer)
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Printf("Error reading: %v\n", err)
		}
	}
}

func writeFunc(conn *Conn, data interface{}) {
	buffer := data.([]byte)
	for j := 0; j < 1000; j++ {
		_, err := conn.Write(buffer)
		if err != nil {
			fmt.Printf("Error writing: %v\n", err)
		}
	}
}

func setupNFunc() interface{} {
	msgs := make([]Msg, 1000)
	for i := 0; i < 1000; i++ {
		msgs[i].Buffer = make([]byte, 1280)
	}
	return msgs
}

func readNFunc(conn *Conn, data interface{}) {
	msgs := data.([]Msg)
	for readMsgs := 0; readMsgs < len(msgs); {
		n, err := conn.ReadN(msgs[readMsgs:])
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Printf("Error reading: %v\n", err)
		}
		readMsgs += n
	}
}

func writeNFunc(conn *Conn, data interface{}) {
	msgs := data.([]Msg)
	for writtenMsgs := 0; writtenMsgs < len(msgs); {
		n, err := conn.WriteN(msgs[writtenMsgs:])
		if err != nil {
			fmt.Printf("Error writing: %v\n", err)
		}
		writtenMsgs += n
	}
}

// Run 1000 writes individually
func BenchmarkReadWrite(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchmark(b, setupFunc, readFunc, writeFunc)
	}
}

func BenchmarkWriteRead(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchmark(b, setupFunc, writeFunc, readFunc)
	}
}

// Run 1000 writes as a single batch operation
func BenchmarkReadNWriteN(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchmark(b, setupNFunc, readNFunc, writeNFunc)
	}
}

func BenchmarkWriteNReadN(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchmark(b, setupNFunc, writeNFunc, readNFunc)
	}
}

func benchmark(b *testing.B, setup SetupFunc, client EndpointFunc, server EndpointFunc) {
	uAddr := make(chan string, 1)
	// Launch server
	go func() {
		file := getRandFile()
		lconn, err := Listen(file)
		if err != nil {
			b.Fatalf("Unable to listen err=%v", err)
		}
		uAddr <- file
		conn, err := lconn.Accept()
		if err != nil {
			b.Fatalf("Unable to accept err=%v", err)
		}
		data := setup()
		server(conn, data)
		conn.Close()
		lconn.Close()
	}()

	// Dial after we have the socket address
	conn, err := DialTimeout(<-uAddr, time.Second)
	if err != nil {
		b.Fatalf("Unable to connect err=%v", err)
	}
	data := setup()
	client(conn, data)
	conn.Close()
}

func setupTestNFunc() interface{} {
	rand.Seed(time.Now().UnixNano())
	msgs := make([]Msg, 1000)
	for i := 0; i < len(msgs); i++ {
		msgs[i].Buffer = make([]byte, rand.Intn(1280))
		for j := 0; j < len(msgs[i].Buffer); j++ {
			msgs[i].Buffer[j] = byte(rand.Intn(256))
		}
	}
	return msgs
}

func testNFunc(t *testing.T, expected interface{}, have interface{}) {
	msgsX := expected.([]Msg)
	msgsY := have.([]Msg)

	Convey("Sent messages should match received messages", t, func() {
		SoMsg("Messages slice length", len(msgsY), ShouldEqual, len(msgsX))
		for i := 0; i < len(msgsX); i++ {
			SoMsg(fmt.Sprintf("MSG%d", i)+" buffers",
				msgsY[i].Buffer[:msgsY[i].Copied], ShouldResemble, msgsX[i].Buffer)
		}
	})
}

func TestReadNWriteN(t *testing.T) {
	uAddr := make(chan string, 1)
	readFinished := make(chan bool, 1)
	serverData := setupNFunc()
	clientData := setupTestNFunc()
	// Launch server
	go func() {
		file := getRandFile()
		lconn, err := Listen(file)
		if err != nil {
			t.Fatalf("Unable to listen err=%v", err)
		}
		uAddr <- file
		conn, err := lconn.Accept()
		if err != nil {
			t.Fatalf("Unable to accept err=%v", err)
		}
		readNFunc(conn, serverData)
		conn.Close()
		lconn.Close()
		readFinished <- true
	}()

	// Dial after we have the socket address
	conn, err := DialTimeout(<-uAddr, time.Second)
	if err != nil {
		t.Fatalf("Unable to connect err=%v", err)
	}
	writeNFunc(conn, clientData)
	conn.Close()

	// Wait for server to finish reading before comparing results
	<-readFinished
	testNFunc(t, clientData, serverData)
}

func getRandFile() string {
	testDir := "/tmp/reliable"
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		os.Mkdir(testDir, 0700)
	}

	r := uint32(time.Now().UnixNano() + int64(os.Getpid()))
	suffix := strconv.Itoa(int(1e9 + r%1e9))[1:]
	return testDir + "/unix." + suffix
}
