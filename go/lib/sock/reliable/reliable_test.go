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
	"net"
	"os"
	"testing"
	"time"

	"github.com/netsec-ethz/scion/go/lib/addr"
)

const (
	sockName = "/tmp/unixtest.sock"
)

func Server(t *testing.T, message string) {
	t.Parallel()

	os.Remove(sockName)

	listener, err := Listen(sockName)
	if err != nil {
		t.Fatalf("Error: %v.", err)
	}

	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	n, err := conn.Write([]byte(message))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if n != len(message) {
		t.Fatalf("Error: expected to write %v bytes, wrote %v.", len(message), n)
	}

	err = conn.Close()
	if err != nil {
		t.Fatalf("Close(): %v", err)
	}
}

func Client(t *testing.T, expected string) {
	t.Parallel()

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
		message := make([]byte, MaxLength)
		n, err := conn.Read(message)
		e <- err
		if err == nil {
			v <- string(message[:n])
		}
	}()

	select {
	case err := <-e:
		if err != nil {
			t.Fatalf("%v", err.Error())
		}
	case <-time.After(time.Second * 3):
		t.Fatalf("Read timed out for socket %v", sockName)
	}

	actual := (<-v).(string)
	if expected != actual {
		t.Fatal("message mismatch", "expected", expected, "actual", actual)
	}

	err := conn.Close()
	if err != nil {
		t.Fatal("close failed", "err", err)
	}
}

func TestConnection(t *testing.T) {
	t.Run("Server", func(t *testing.T) { Server(t, "ping") })
	t.Run("Client", func(t *testing.T) { Client(t, "ping") })
}

func ExampleRegister(t *testing.T) {
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
			t.Fatalf("%v", err)
		}
	case <-time.After(time.Second * 3):
		t.Fatalf("Dispatcher registration timed out")
	}
}
