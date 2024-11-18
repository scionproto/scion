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
// writes to a separately allocated buffer (such as a packet's raw buffer). It is designed with the
// assumption that the buffer is large enough for all the prepends and appends that will be thrown
// at it, so there never is a need for realocation. Should that be false, it would be a severe
// internal error; i.e. Panic is fine. The starting point of appends and prepends is the middle of
// the buffer. It is designed to be a local variable, so New() returns a value.  The entire buffer
// underpinning the given slice may be used; that is, from the start up to the remaining capacity.
type serializeProxy struct {
	data   []byte
	start  int // data[0] == buf[0] (bc changing it is one way), so we keep track of the real start.
	layers []gopacket.LayerType
}

func newSerializeProxy(buf []byte) serializeProxy {
	serBuf := serializeProxy{
		data: buf,
	}
	serBuf.Clear()
	return serBuf
}

func (s *serializeProxy) Clear() error {
	s.start = cap(s.data) / 2
	s.data = s.data[:s.start]
	s.layers = s.layers[:0]
	return nil
}

func (s *serializeProxy) PrependBytes(num int) ([]byte, error) {
	s.start -= num
	return s.data[s.start : s.start+num], nil
}

func (s *serializeProxy) AppendBytes(num int) ([]byte, error) {
	ol := len(s.data)
	nl := ol + num
	s.data = s.data[:nl]
	return s.data[ol:nl], nil
}

func (s *serializeProxy) Bytes() []byte {
	return s.data[s.start:]
}

func (s *serializeProxy) Layers() []gopacket.LayerType {
	return s.layers
}

func (s *serializeProxy) PushLayer(l gopacket.LayerType) {
	s.layers = append(s.layers, l)
}
