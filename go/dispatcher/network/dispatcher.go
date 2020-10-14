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

package network

import (
	"os"

	"github.com/scionproto/scion/go/dispatcher/dispatcher"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

type Dispatcher struct {
	UnderlaySocket    string
	ApplicationSocket string
	SocketFileMode    os.FileMode
}

func (d *Dispatcher) ListenAndServe() error {
	dispServer, err := dispatcher.NewServer(d.UnderlaySocket, nil, nil)
	if err != nil {
		return err
	}
	defer dispServer.Close()

	dispServerConn, err := reliable.Listen(d.ApplicationSocket)
	if err != nil {
		return err
	}
	defer dispServerConn.Close()
	if err := os.Chmod(d.ApplicationSocket, d.SocketFileMode); err != nil {
		return common.NewBasicError("chmod failed", err, "socket file", d.ApplicationSocket)
	}

	errChan := make(chan error)
	go func() {
		defer log.HandlePanic()
		errChan <- dispServer.Serve()
	}()

	go func() {
		defer log.HandlePanic()
		dispServer := &AppSocketServer{
			Listener:   dispServerConn,
			DispServer: dispServer,
		}
		errChan <- dispServer.Serve()
	}()

	return <-errChan
}
