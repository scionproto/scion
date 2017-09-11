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
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

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
