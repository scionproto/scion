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

package dataplane

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPktReader(t *testing.T) {
	raw := make([]byte, 10)
	p := newPktRing()

	// If the ring is empty, nil is returned.
	pkt, n := p.Read(false)
	assert.Equal(t, 0, n)
	assert.Nil(t, pkt)

	// Pass one packet.
	res := p.Write(raw, false)
	assert.Equal(t, 1, res)
	pkt, n = p.Read(true)
	assert.Equal(t, 1, n)
	assert.Equal(t, raw, pkt)
	pkt, n = p.Read(false)
	assert.Equal(t, 0, n)
	assert.Nil(t, pkt)

	// Pass multiple packets.
	res = p.Write(raw, false)
	assert.Equal(t, 1, res)
	res = p.Write(raw, true)
	assert.Equal(t, 1, res)
	res = p.Write(raw, false)
	assert.Equal(t, 1, res)
	pkt, n = p.Read(false)
	assert.Equal(t, 1, n)
	assert.Equal(t, raw, pkt)
	pkt, n = p.Read(true)
	assert.Equal(t, 1, n)
	assert.Equal(t, raw, pkt)
	pkt, n = p.Read(true)
	assert.Equal(t, 1, n)
	assert.Equal(t, raw, pkt)
	pkt, n = p.Read(false)
	assert.Equal(t, 0, n)
	assert.Nil(t, pkt)

	// Close the packet ring.
	res = p.Write(raw, false)
	assert.Equal(t, 1, res)
	p.Close()
	pkt, n = p.Read(true)
	assert.Equal(t, 1, n)
	assert.Equal(t, raw, pkt)
	pkt, n = p.Read(true)
	assert.Equal(t, -1, n)
	assert.Nil(t, pkt)
}
