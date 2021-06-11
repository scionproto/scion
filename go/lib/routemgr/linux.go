// Copyright 2021 Anapaya Systems
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

package routemgr

import (
	"sync"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/gateway/control"
)

// Linux is a one-way exporter of routes to Linux kernel.
type Linux struct {
	// DeviceManager is used to export routes to external routing tables (e.g., Linux).
	DeviceManager control.DeviceManager

	mtx sync.Mutex
	// exportedRoutes stores routes published by the local process.
	exportedRoutes RouteDB
	// externalRoutes stores routes received from quagga.
	closeChan chan struct{}
}

func (l *Linux) init() {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	if l.closeChan == nil {
		l.closeChan = make(chan struct{})
		go func() {
			defer log.HandlePanic()
			l.exportedRoutes.Run()
		}()
	}
}

func (l *Linux) NewPublisher() control.Publisher {
	return l.exportedRoutes.NewPublisher()
}

func (l *Linux) Close() {
	l.init()
	close(l.closeChan)
}

func (l *Linux) Run() {
	l.init()
	consumer := l.exportedRoutes.NewConsumer()
Top:
	for {
		select {
		case update := <-consumer.Updates():
			err := l.publishToLinux(update)
			if err != nil {
				log.Error("Error when publishing to Linux", "err", err)
			}
		case <-l.closeChan:
			// Closed by the user.
			break Top
		}
	}
	consumer.Close()
	l.exportedRoutes.Close()
}

func (l *Linux) publishToLinux(update control.RouteUpdate) error {
	handle, err := l.DeviceManager.Get(update.IA)
	if err != nil {
		return serrors.WrapStr("retrieving device for ISD-AS", err, "isd_as", update.IA)
	}
	defer func() {
		if err := handle.Close(); err != nil {
			log.Info("unable to clean up device", "isd_as", update.IA, "err", err)
		}
	}()
	if update.IsAdd {
		return handle.AddRoute(&update.Route)
	}
	return handle.DeleteRoute(&update.Route)
}

func (l *Linux) Diagnostics() control.Diagnostics {
	return l.exportedRoutes.Diagnostics()
}
