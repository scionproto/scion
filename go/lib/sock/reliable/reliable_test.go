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
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
)

func Server(t *testing.T, sockName string, timeoutOK bool) []byte {
	os.Remove(sockName)
	listener, err := Listen(sockName)
	if err != nil {
		t.Fatalf("Error: %v.", err)
	}

	errChan := make(chan error, 1)
	dataChan := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatalf("Error: %v", err)
		}

		// Sleep so we get all the data in one chunk
		time.Sleep(300 * time.Millisecond)
		buf := make([]byte, 128)
		n, err := conn.UnixConn.Read(buf)
		if err != nil {
			errChan <- err
			return
		}

		err = conn.Close()
		if err != nil {
			errChan <- err
			return
		}

		errChan <- nil
		dataChan <- buf[:n]
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("%v", err.Error())
		}
	case <-time.After(time.Second * 1):
		if timeoutOK {
			// Just return
			return []byte{}
		}
		t.Fatalf("Read timed out waiting for message from Client")
	}

	return <-dataChan
}

func Client(t *testing.T, sockName string, msg []byte, dst AppAddr) {
	errChan := make(chan error, 1)
	dataChan := make(chan interface{}, 1)

	go func() {
		// Sleep to avoid connecting before server is up
		time.Sleep(200 * time.Millisecond)
		conn, err := Dial(sockName)
		errChan <- err
		if err == nil {
			dataChan <- conn
		}
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("%v", err.Error())
		}
	case <-time.After(time.Second * 3):
		t.Fatalf("Dial timed out for socket %v", sockName)
	}
	conn := (<-dataChan).(*Conn)

	go func() {
		_, err := conn.WriteTo(msg, dst)
		errChan <- err
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("%v", err.Error())
		}
	case <-time.After(time.Second * 3):
		t.Fatalf("Write timed out for socket %v", sockName)
	}

	// Give the server time to get the data
	err := conn.Close()
	if err != nil {
		t.Fatal("close failed", "err", err)
	}
}

func ClientRegister(t *testing.T, sockName string, ia *addr.ISD_AS, dst AppAddr) {
	errChan := make(chan error, 1)
	go func() {
		// Sleep to avoid connecting before server is up
		time.Sleep(200 * time.Millisecond)
		Register(sockName, ia, dst)
		errChan <- nil
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("%v", err.Error())
		}
	case <-time.After(time.Second * 3):
		t.Fatalf("Dial timed out for socket %v", sockName)
	}
}

func TestWriteTo(t *testing.T) {
	nilAddr, _ := addr.HostFromRaw(nil, addr.HostTypeNone)
	testCases := []struct {
		payload string
		dst     AppAddr
		want    []byte
	}{
		{"", AppAddr{Addr: nilAddr, Port: 0},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 0}},
		{"test", AppAddr{Addr: nilAddr, Port: 0},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 4, 't', 'e', 's', 't'}},
		{"foo", AppAddr{Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 3,
				127, 0, 0, 1, 0, 80, 'f', 'o', 'o'}},
		{"bar", AppAddr{Addr: addr.HostFromIP(net.IPv6loopback), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 3,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				0, 80, 'b', 'a', 'r'}}}

	Convey("Client sending message to Server using WriteTo", t, func() {
		Convey("Server should receive correct raw messages", func() {
			for _, tc := range testCases {
				Convey(fmt.Sprintf("Client sent message \"%v\"", tc.payload), func() {
					sockName := fmt.Sprintf("/tmp/reliable%v.sock", rand.Uint32())

					c := make(chan []byte, 1)
					go func(t *testing.T) {
						c <- Server(t, sockName, false)
					}(t)

					go func(t *testing.T) {
						Client(t, sockName, []byte(tc.payload), tc.dst)
					}(t)

					mc := <-c

					// Wait for goroutines to finish
					So(mc, ShouldResemble, tc.want)
					// Wait for cleanup to finish
				})
			}
		})
	})
}

func TestRegister(t *testing.T) {
	nilAddr, _ := addr.HostFromRaw(nil, addr.HostTypeNone)

	testCases := []struct {
		ia        addr.ISD_AS
		dst       AppAddr
		want      []byte
		timeoutOK bool
	}{
		{addr.ISD_AS{I: 1, A: 10}, AppAddr{Addr: nilAddr, Port: 0},
			[]byte{}, true},
		{addr.ISD_AS{I: 2, A: 21}, AppAddr{Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 13,
				3, 17, 0, 32, 0, 21, 0, 80, 1, 127, 0, 0, 1}, false},
		{addr.ISD_AS{I: 2, A: 21}, AppAddr{Addr: addr.HostFromIP(net.IPv6loopback), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 25,
				3, 17, 0, 32, 0, 21, 0, 80, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, false}}

	Convey("Client registering to SCIOND", t, func() {
		Convey("SCIOND should receive correct raw messages", func() {
			for _, tc := range testCases {
				Convey(fmt.Sprintf("Client registered to %v, %v", tc.ia, tc.dst), func() {
					sockName := fmt.Sprintf("/tmp/reliable%v.sock", rand.Uint32())
					c := make(chan []byte, 1)
					go func(t *testing.T) {
						c <- Server(t, sockName, tc.timeoutOK)
					}(t)

					go func(t *testing.T) {
						ClientRegister(t, sockName, &tc.ia, tc.dst)
					}(t)

					mc := <-c

					So(mc, ShouldResemble, tc.want)
				})
			}
		})
	})
}
