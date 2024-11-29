// Copyright 2024 SCION Association
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

package router

import (
	"github.com/google/gopacket"
)

// serializeProxy implements gopacket.SerializeBuffer. It is a very simple implementation that
// writes to a separately allocated buffer (such as a packet's raw buffer). Space is added to the
// buffer via PrependBytes and AppendBytes simply by changing the starting point and length of the
// data slice. No reallocation is ever performed. Running out of append or prepend space triggers a
// panic. It is designed to be a local variable, so New() returns a value. The entire buffer
// underpinning the given slice may be used; that is, from the start up to the remaining capacity.
type serializeProxy struct {

	// The slice's offset can't be changed as that is irreversible.
	// So we keep track of the prepend point separately from the slice.

	restart int // the value to reset start to during Clear().
	start   int // current start of the useful data in the buffer.
	data    []byte
	layers  []gopacket.LayerType
}

// newSerializeProxy returns a new serializeProxy. The initial prepend/append point is set to the
// end of the buffer in anticipation of AppendBytes never being used. The prepend/append point can
// be changed when calling clear().
func newSerializeProxy(buf []byte) serializeProxy {
	return newSerializeProxyStart(buf, cap(buf))
}

// newSerializeProxyStart returns a new serializeProxy. The initial prepend/append point is set to
// the given start value. This has the same effect as calling clear(statr).
func newSerializeProxyStart(buf []byte, start int) serializeProxy {
	serBuf := serializeProxy{
		data: buf,
	}
	serBuf.clear(start)
	return serBuf
}

// Resets the buffer to empty and sets the initial prepend/append point to the given position.
// The next prepend will claim an area ending with index newStart - 1. The next append will claim an
// area starting with index newStart.
func (s *serializeProxy) clear(newStart int) {
	s.restart = newStart
	s.start = newStart
	s.data = s.data[:newStart]
	s.layers = s.layers[:0]
}

// Implements serializeBuffer.Clear(). This implementation never returns an error.
// The initial prepend/append point is reset to that which was set by the last call to clear().
func (s *serializeProxy) Clear() error {
	s.clear(s.restart)
	return nil
}

// PrependBytes implements serializeBuffer.PrependBytes(). It never returns an error.
// It can panic if attenpting to prepend before the start of the buffer.
func (s *serializeProxy) PrependBytes(num int) ([]byte, error) {
	s.start -= num
	return s.data[s.start : s.start+num], nil
}

// AppendBytes implements serializeBuffer.AppendBytes(). It never returns an error.
// It can panic if attempting to append past the end of the buffer.
func (s *serializeProxy) AppendBytes(num int) ([]byte, error) {
	ol := len(s.data)
	nl := ol + num
	s.data = s.data[:nl]
	return s.data[ol:nl], nil
}

// Bytes implements serializeBuffer.Bytes(). It returns a slice that represents the useful portion
// of the buffer. That is the portion that contains all the prepended and appended bytes since the
// last call to Clear().
func (s *serializeProxy) Bytes() []byte {
	return s.data[s.start:]
}

// Bytes implements serializeBuffer.Layers.
func (s *serializeProxy) Layers() []gopacket.LayerType {
	return s.layers
}

// Bytes implements serializeBuffer.PushLayer.
func (s *serializeProxy) PushLayer(l gopacket.LayerType) {
	s.layers = append(s.layers, l)
}
