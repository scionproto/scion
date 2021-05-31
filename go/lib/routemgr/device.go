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
	"encoding/base32"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/gateway/control"
)

const (
	DefaultDeviceName = "tun0"
	IATunDevicePrefix = "s."
)

type destructionCallback func()

// deviceHandle wraps reference counting around a base device handler.
//
// Access this object only through its methods.
type deviceHandle struct {
	// mtx protects access to the reference counter and base device handle. API calls to the
	// base handle are made without holding the lock. However, the handle is checked before and
	// after the API call to see if it was destroyed, and the
	// ObjectDestroyedError error is returned in this case. The error will wrap
	// any error returned by the call. This allows for callers to easily check
	// whether the resource was destroyed without knowing the type of the underlying device.
	//
	// To ensure that io.Reader and io.Writer semantics are preserved, the
	// number of bytes read/written is always returned irrespective of whether
	// ObjectDestroyedError or a device error occurred.
	mtx      sync.RWMutex
	base     control.DeviceHandle
	refCount int
	// destructionCallback is a function that runs exactly once after the base
	// handle has been freed. The callback executes outside the mutex. If nil,
	// no callback is executed. The callback needs to be safe for concurrent
	// calls by multiple goroutines.
	destructionCallback destructionCallback
}

func (h *deviceHandle) Close() error {
	// The callback runs outside the mutex, thus avoiding deadlocks in deviceHandle
	// methods if for whatever reason the destruction callback blocks.
	err, destructionF := h.innerClose()
	if destructionF != nil {
		destructionF()
	}
	return err
}

// innerClose closes the base handle and returns a cleanup function. The cleanup
// function must always be executed, even if the error return value is non-nil.
func (h *deviceHandle) innerClose() (error, destructionCallback) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if h.refCount == 0 {
		return serrors.New("handle closed too many times"), nil
	}

	h.refCount--
	if h.refCount == 0 {
		return h.base.Close(), h.destructionCallback
	}
	return nil, nil
}

// newDeviceHandle creates a new reference counting handle on top of base.
// If destructionCallback is not nil, it will be called after base is closed.
func newDeviceHandle(base control.DeviceHandle,
	destructionCallback destructionCallback) *deviceHandle {

	return &deviceHandle{
		base:                base,
		destructionCallback: destructionCallback,
		refCount:            1,
	}
}

func (h *deviceHandle) incRefs() {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if h.refCount == 0 {
		panic("bug: attempted to get reference to destroyed object")
	}
	h.refCount++
}

func (h *deviceHandle) destroyed() bool {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	return h.refCount == 0
}

func (h *deviceHandle) Read(b []byte) (int, error) {
	return h.ioWrapper(h.base.Read, b)
}

func (h *deviceHandle) Write(b []byte) (int, error) {
	return h.ioWrapper(h.base.Write, b)
}

// ioWrapper is a type-safe invoker of io.Reader/io.Writer ops. It calls f on b
// and returns the result.
func (h *deviceHandle) ioWrapper(f func([]byte) (int, error), b []byte) (int, error) {
	if h.destroyed() {
		return 0, control.ObjectDestroyedError
	}
	n, err := f(b)
	if err != nil && h.destroyed() {
		// always give the correct number of bytes to the caller (e.g., so it can know up to
		// where it read/wrote on a device which supports streaming).
		return n, serrors.Wrap(control.ObjectDestroyedError, err)
	}
	return n, err
}

func (h *deviceHandle) AddRoute(r *control.Route) error {
	return h.routeWrapper(h.base.AddRoute, r)
}

func (h *deviceHandle) DeleteRoute(r *control.Route) error {
	return h.routeWrapper(h.base.DeleteRoute, r)
}

// ioWrapper is a type-safe invoker of route creation/deletion ops. It calls f
// on r and returns the result.
func (h *deviceHandle) routeWrapper(f func(*control.Route) error, r *control.Route) error {
	if h.destroyed() {
		return control.ObjectDestroyedError
	}
	err := f(r)
	if err != nil && h.destroyed() {
		return serrors.Wrap(control.ObjectDestroyedError, err)
	}
	return err
}

// SingleDeviceManager opens a single device for all ISD-ASes.
type SingleDeviceManager struct {
	// DeviceOpener is the object used to create new handles.
	DeviceOpener control.DeviceOpener

	mtx    sync.Mutex
	device *deviceHandle
}

// Get returns a handle to the device for the ISD-AS. If no device exists, one will be created.
// If a device already exists, a handle to the existing device is returned. The caller must
// Close the handle to guarantee that resources will be cleaned up.
func (m *SingleDeviceManager) Get(ia addr.IA) (control.DeviceHandle, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.DeviceOpener == nil {
		return nil, serrors.New("no DeviceOpener set")
	}

	if m.device != nil && !m.device.destroyed() {
		m.device.incRefs()
		return m.device, nil
	}

	device, err := m.DeviceOpener.Open(ia)
	if err != nil {
		return nil, err
	}
	m.device = newDeviceHandle(device, nil)
	return m.device, nil
}

// MultiDeviceManager opens one device for each ISD-AS.
type MultiDeviceManager struct {
	// DeviceOpener is used to create new resources for handles returned by Get.
	DeviceOpener control.DeviceOpener

	mtx     sync.Mutex
	devices map[addr.IA]*deviceHandle
}

// Get returns a handle to the device for the ISD-AS. If no device exists, one will be created.
// If a device already exists, a handle to the existing device is returned. The caller must
// Close the handle to guarantee that resources will be cleaned up.
//
// Devices are created with a name composed of the default tunnel device prefix and
// an unpadded base32 representation of the ISD-AS.
func (m *MultiDeviceManager) Get(ia addr.IA) (control.DeviceHandle, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.DeviceOpener == nil {
		return nil, serrors.New("DeviceManager not set")
	}

	if m.devices == nil {
		m.devices = make(map[addr.IA]*deviceHandle)
	}

	if m.devices[ia] == nil || m.devices[ia].destroyed() {
		device, err := m.DeviceOpener.Open(ia)
		if err != nil {
			return nil, err
		}
		m.devices[ia] = newDeviceHandle(device, m.newDeletionCallback(ia))
	} else {
		m.devices[ia].incRefs()
	}

	return m.devices[ia], nil
}

// Size returns the number of existing devices.
func (m *MultiDeviceManager) Size() int {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	return len(m.devices)
}

func (m *MultiDeviceManager) newDeletionCallback(ia addr.IA) destructionCallback {
	return func() {
		m.mtx.Lock()
		defer m.mtx.Unlock()

		delete(m.devices, ia)
	}
}

// Base32TunnelName is a device naming function that constructs Linux tun names using
// the base32 encoding of an IA number.
func Base32TunnelName(ia addr.IA) string {
	b := make([]byte, 8)
	ia.Write(b)
	return IATunDevicePrefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// FixedTunnelName returns a device naming function that uses name for every IA.
func FixedTunnelName(name string) func(addr.IA) string {
	return func(addr.IA) string {
		return name
	}
}
