// Copyright 2019 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package ingress

import (
	"context"
	"io"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/sig/internal/sigcmn"
)

func Init(tunIO io.ReadWriteCloser) {
	fatal.Check()
	conn, err := sigcmn.Network.Listen(context.Background(), "udp",
		&net.UDPAddr{IP: sigcmn.DataAddr, Port: sigcmn.DataPort}, addr.SvcNone)
	if err != nil {
		log.Crit("Unable to initialize ingress connection", "err", err)
		fatal.Fatal(err)
	}
	d := NewDispatcher(tunIO, conn)
	go func() {
		defer log.HandlePanic()
		if err := d.Run(); err != nil {
			log.Crit("Ingress dispatcher error", "err", err)
			fatal.Fatal(err)
		}
	}()
}
