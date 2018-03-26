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

// End to end test for SCIOND. This is a separate package because it is
// expected to grow. If it doesn't, we just merge it into go/sciond.
package e2etest

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/loader"
)

func TestASInfo(t *testing.T) {
	dir, deleteDirTree := setupDirTree(t)
	defer deleteDirTree()
	sock := xtest.MustTempFileName(dir, "rsock")
	stopServer := StartServer(t, dir, sock)
	defer stopServer()
	conn, stopClient := StartClient(t, sock)
	defer stopClient()

	Convey("Send and receive ASInfo", t, func() {
		reply, err := conn.ASInfo(addr.IA{I: 1, A: 1})
		SoMsg("err", err, ShouldBeNil)
		expReply := &sciond.ASInfoReply{
			Entries: []sciond.ASInfoReplyEntry{
				{
					RawIsdas: addr.IA{I: 1, A: 1}.IAInt(),
					Mtu:      1337,
					IsCore:   true,
				},
			},
		}
		SoMsg("reply", reply, ShouldResemble, expReply)
	})
}

func setupDirTree(t *testing.T) (string, func()) {
	t.Helper()

	name, err := ioutil.TempDir("", "test-sciond-e2e-")
	if err != nil {
		t.Fatalf(err.Error())
	}
	return name, func() {
		os.RemoveAll(name)
	}
}

func StartClient(t *testing.T, file string) (sciond.Connector, func()) {
	t.Helper()

	sd := sciond.NewService(file)
	conn, err := sd.Connect()
	if err != nil {
		t.Fatalf("unable to connect to sciond err=%v", err)
	}

	return conn, func() {
		conn.Close()
	}
}

func StartServer(t *testing.T, dir, file string) func() {
	t.Helper()

	binary := loader.Binary{
		Target: "github.com/scionproto/scion/go/sciond",
		Dir:    dir,
		Prefix: "sciond",
	}
	binary.Build()
	t.Log("Build succeeded")

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	cmd := binary.Cmd(
		"-id", "sdtest",
		"-reliable", file,
		"-log.console", "debug",
		"-prom", fmt.Sprintf("127.0.0.1:%d", 30000+r.Intn(1000)),
	)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("unable to run sciond binary, err=%v", err)
	}
	// Give the server time to start
	time.Sleep(time.Second)

	return func() {
		cmd.Process.Kill()
	}
}
