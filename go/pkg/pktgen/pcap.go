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

package pktgen

import (
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/scionproto/scion/go/lib/serrors"
)

// StorePcap stores a Pcap file with the given raw packet and file name.
func StorePcap(file string, pkt []byte) error {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return serrors.WrapStr("creating file", err, "file", file)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return serrors.WrapStr("writing header", err, "file", file)
	}
	c := gopacket.CaptureInfo{
		Length:        len(pkt),
		CaptureLength: len(pkt),
	}
	if err := w.WritePacket(c, pkt); err != nil {
		return serrors.WrapStr("writing packet", err, "file", file)
	}
	return nil
}
