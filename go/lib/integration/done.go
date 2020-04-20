// Copyright 2020 Anapaya Systems
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

package integration

import (
	"io/ioutil"
	"net"
	"os"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/integration/progress"
	"github.com/scionproto/scion/go/lib/log"
)

// ListenDone opens a RPC server to listen for done signals.
func ListenDone(onDone func(src, dst addr.IA)) (string, func(), error) {
	if err := os.MkdirAll("logs/socks", os.ModePerm); err != nil {
		return "", nil, err
	}
	file, err := ioutil.TempFile("logs/socks", "integration-*.sock")
	if err != nil {
		return "", nil, err
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		return "", nil, err
	}
	if err := os.Remove(name); err != nil {
		return "", nil, err
	}
	l, err := net.Listen("unix", name)
	if err != nil {
		return "", nil, err
	}
	srv := progress.Server{OnDone: onDone}
	go func() {
		defer log.HandlePanic()
		srv.Serve(l)
	}()
	return name, func() { os.Remove(name) }, nil
}
