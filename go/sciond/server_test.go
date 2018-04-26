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

package main

import (
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestASInfo(t *testing.T) {
	dir, deleteDirTree := setupDirTree(t)
	defer deleteDirTree()
	sock := xtest.MustTempFileName(dir, "rsock")
	defer StartServer(t, dir, sock)()
	conn, stopClient := StartClient(t, sock)
	defer stopClient()

	Convey("Send and receive ASInfo", t, func() {
		reply, err := conn.ASInfo(xtest.MustParseIA("1-ff00:0:1"))
		SoMsg("err", err, ShouldBeNil)
		expReply := &sciond.ASInfoReply{
			Entries: []sciond.ASInfoReplyEntry{
				{
					RawIsdas: xtest.MustParseIA("1-ff00:0:1").IAInt(),
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

	cmd := exec.Command(
		"../../bin/sciond",
		"-id", "sdtest",
		"-reliable", file,
		"-log.console", "crit",
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

func TestMain(m *testing.M) {
	// Discard client logging messages
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
