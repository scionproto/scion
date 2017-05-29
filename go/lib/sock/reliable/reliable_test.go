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
	"net"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
)

const (
	sockName = "/tmp/unixtest.sock"
)

func Server(t *testing.T, timeoutOK bool) []byte {
	os.Remove(sockName)
	listener, err := Listen(sockName)
	if err != nil {
		t.Fatalf("Error: %v.", err)
	}

	e := make(chan error, 1)
	v := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatalf("Error: %v", err)
		}

		buf := make([]byte, 128)
		n, err := conn.UnixConn.Read(buf)
		if err != nil {
			e <- err
			return
		}

		err = conn.Close()
		if err != nil {
			e <- err
			return
		}

		e <- nil
		v <- buf[:n]
	}()

	select {
	case err := <-e:
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
	return <-v
}

func Client(t *testing.T, message []byte, destination AppAddr) {
	e := make(chan error, 1)
	v := make(chan interface{}, 1)

	go func() {
		// Sleep to avoid connecting before server is up
		time.Sleep(200 * time.Millisecond)
		conn, err := Dial(sockName)
		e <- err
		if err == nil {
			v <- conn
		}
	}()

	select {
	case err := <-e:
		if err != nil {
			t.Fatalf("%v", err.Error())
		}
	case <-time.After(time.Second * 3):
		t.Fatalf("Dial timed out for socket %v", sockName)
	}
	conn := (<-v).(*Conn)

	go func() {
		_, err := conn.WriteTo(message, destination)
		e <- err
	}()

	select {
	case err := <-e:
		if err != nil {
			t.Fatalf("%v", err.Error())
		}
	case <-time.After(time.Second * 3):
		t.Fatalf("Write timed out for socket %v", sockName)
	}

	err := conn.Close()
	if err != nil {
		t.Fatal("close failed", "err", err)
	}
}

func ClientRegister(t *testing.T, ia *addr.ISD_AS, destination AppAddr) {
	e := make(chan error, 1)
	go func() {
		// Sleep to avoid connecting before server is up
		time.Sleep(200 * time.Millisecond)
		Register(sockName, ia, destination)
		e <- nil
	}()

	select {
	case err := <-e:
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
		payload     string
		destination AppAddr
		want        []byte
	}{
		{"", AppAddr{Addr: nilAddr, Port: 0},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 0}},
		{"test", AppAddr{Addr: nilAddr, Port: 0},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 4, 0, 0, 0, 't', 'e', 's', 't'}},
		{"foo", AppAddr{Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 3, 0, 0, 0,
				127, 0, 0, 1, 80, 0, 'f', 'o', 'o'}},
		{"bar", AppAddr{Addr: addr.HostFromIP(net.IPv6loopback), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 3, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				80, 0, 'b', 'a', 'r'}}}

	Convey("Client sending message to Server using WriteTo", t, func() {
		Convey("Server should receive correct raw messages", func() {
			for _, tc := range testCases {
				Convey(fmt.Sprintf("Client sent message \"%v\"", tc.payload), func() {
					c := make(chan []byte, 1)
					go func(t *testing.T) {
						c <- Server(t, false)
					}(t)

					go func(t *testing.T) {
						Client(t, []byte(tc.payload), tc.destination)
					}(t)

					mc := <-c

					// Wait for goroutines to finish
					time.Sleep(200 * time.Millisecond)
					So(mc, ShouldResemble, tc.want)
					// Wait for cleanup to finish
					time.Sleep(200 * time.Millisecond)
				})
			}
		})
	})
}

func TestRegister(t *testing.T) {
	nilAddr, _ := addr.HostFromRaw(nil, addr.HostTypeNone)

	testCases := []struct {
		ia          addr.ISD_AS
		destination AppAddr
		want        []byte
		timeoutOK   bool
	}{
		{addr.ISD_AS{I: 1, A: 10}, AppAddr{Addr: nilAddr, Port: 0},
			[]byte{}, true},
		{addr.ISD_AS{I: 2, A: 21}, AppAddr{Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 13, 0, 0, 0,
				3, 17, 0, 32, 0, 21, 0, 80, 1, 127, 0, 0, 1}, false},
		{addr.ISD_AS{I: 2, A: 21}, AppAddr{Addr: addr.HostFromIP(net.IPv6loopback), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 25, 0, 0, 0,
				3, 17, 0, 32, 0, 21, 0, 80, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, false}}

	Convey("Client registering to SCIOND", t, func() {
		Convey("SCIOND should receive correct raw messages", func() {
			for _, tc := range testCases {
				Convey(fmt.Sprintf("Client registered to %v, %v", tc.ia, tc.destination), func() {
					c := make(chan []byte, 1)
					go func(t *testing.T) {
						c <- Server(t, tc.timeoutOK)
					}(t)

					go func(t *testing.T) {
						ClientRegister(t, &tc.ia, tc.destination)
					}(t)

					mc := <-c

					time.Sleep(200 * time.Millisecond)
					So(mc, ShouldResemble, tc.want)
					time.Sleep(200 * time.Millisecond)
				})
			}
		})
	})
}

func ExampleRegister() {
	dispatcher := "/run/shm/dispatcher/default.sock"
	e := make(chan error)

	go func() {
		ia, _ := addr.IAFromString("1-10")
		host := addr.HostFromIP(net.IPv4(127, 0, 0, 42))
		port := uint16(40001)

		_, err := Register(dispatcher, ia, AppAddr{Addr: host, Port: port})
		e <- err
	}()

	select {
	case err := <-e:
		if err != nil {
			fmt.Printf("Error: %v", err)
		}
	case <-time.After(time.Second * 3):
		fmt.Printf("Dispatcher registration timed out")
	}

	fmt.Println("Registered with 1,10,127.0.0.42:40001")

	// Output:
	// Registered with 1,10,127.0.0.42:40001
}
