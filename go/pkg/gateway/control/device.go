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

package control

import (
	"io"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
)

// DeviceOpener can be used to open readable/writeable objects that support
// IPv4/IPv6 routing. Typically, this is a Linux network device.
type DeviceOpener interface {
	Open(name string) (DeviceHandle, error)
}

// DeviceOpenerFunc is a function type that implements DeviceOpener.
type DeviceOpenerFunc func(name string) (DeviceHandle, error)

func (f DeviceOpenerFunc) Open(name string) (DeviceHandle, error) {
	return f(name)
}

var (
	// ObjectDestroyedError is returned by DeviceHandle API calls if the handle has been closed
	// before or during the API call. If the device is closed while the API call is ongoing, it is
	// not guaranteed that the returned error is ObjectDestroyedError, because the device access
	// might have completed before the close, but the API call hasn't finished yet.
	ObjectDestroyedError = serrors.New("object was destroyed")
)

// DeviceHandle models an object that implements the reading and writing of packets and supports
// the addition of IPv4 and IPv6 routes through it. To destroy the interface, call Close. Calling
// Close multiple times is undefined behavior. Check the documentation of the component returning
// the DeviceHandle to see how Close should be called.
type DeviceHandle interface {
	io.ReadWriteCloser
	// AddRoute creates a route going through the device.
	AddRoute(r *Route) error
	// DeleteRoute destroys a route going through the device.
	DeleteRoute(r *Route) error
}

// DeviceManager returns handles to shared device objects. If an error is returned, no resource
// has been created.
type DeviceManager interface {
	Get(ia addr.IA) (DeviceHandle, error)
}
