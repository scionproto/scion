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

// mmbm measures the performance of memory copy, as performed by the Go runtime.
// The output is expressed in MebiBytes per second.
//
// The go implementation of memcpy/memmove isn't necessarily the highest performing, but it is close
// to that of glibc's and it has the advantages of being independent from any given libc
// implementation. musl_libc's implementation, for example performs much worse.
//
// TODO(jiceatscion): For now, the whole benchmark is restricted to measuring
// and predicting an ideal 100% in-cache performance. In the future, we will
// extend the model to multiple caching circumstances and execute this benchmark with
// different cache size targets.
package main

import (
	"flag"
	"fmt"
	"testing"
	"unsafe"
)

// The arena that we play with. We do not necessarily use it all in a given test case.
const allBufs = 8192
const bufSize = 4096

type block struct {
	packet struct {
		oneByte uint8
		theRest [171]uint8
	}
	tail [bufSize - 172]uint8
}

var buf [allBufs]block

// We arrange to cycle through all the blocks from two sets (much like a steady state
// saturated router would need to). We go backward in an attempt to defeat a prefetch algorithm.
// we go 2 by 2 in order to avoid reusing a page (in case buffers are not aligned).
var last int = 0

func nextPair(max int) (int, int) {
	last = (last + max - 2) % max
	return last, (last + max/2) % max // the second one is on the opposite side of the ring.
}

// Just in case Go would take advantage of the initial zero value, somehow.
// This also allocates the memory pages and get everything we do not touch
// out of the cache (and some or all of what we touch in it).
func writeBuf(numBufs int, cpSize int) {
	for i := 0; i < numBufs; i++ {
		buf[i].packet.oneByte = uint8(0)
		for j := 1; j < 172; j++ {
			buf[i].packet.theRest[j-1] = uint8(j % 256)
		}
		for j := 172; j < cpSize; j++ {
			buf[i].tail[j-172] = uint8(j % 256)
		}
	}
}

// Copy from a block to another
func benchmarkCopy(b *testing.B, numBufs int, copySize int) {
	if copySize == 1 {
		for i := 0; i < b.N; i++ {
			dst, src := nextPair(numBufs)
			buf[dst].packet.oneByte = buf[src].packet.oneByte
		}
		return
	}
	if copySize == 172 {
		for i := 0; i < b.N; i++ {
			dst, src := nextPair(numBufs)
			buf[dst].packet = buf[src].packet
		}
		return
	}
	if copySize == 4096 {
		for i := 0; i < b.N; i++ {
			dst, src := nextPair(numBufs)
			buf[dst] = buf[src]
		}
		return
	}
	panic("Size not supported")
}

func tc(name string, numBufs int, packetSize int) (float64, float64) {
	var res testing.BenchmarkResult
	writeBuf(numBufs, packetSize)
	res = testing.Benchmark(func(b *testing.B) {
		benchmarkCopy(b, numBufs, packetSize)
	})

	bytes := uint64(res.N) * uint64(packetSize)
	megaBytes := float64(bytes) / (1024 * 1024)

	mbps := megaBytes / res.T.Seconds()
	mpps := float64(res.N) / float64(res.T.Microseconds())

	// fmt.Printf("%s (%d, %d): %.2f MB/s %.2f Mpacket/s\n", name, numBufs, packetSize, mbps, mpps)

	return mbps, mpps
}

func main() {
	testing.Init()
	flag.VisitAll(func(f *flag.Flag) {
		if f.Name == "test.benchtime" {
			err := f.Value.Set("5s") // below that random outliers show-up.
			if err != nil {
				panic(err)
			}
		}
	})

	// It is difficult to force go to align arrays on page boundaries, but we can
	// correct for the effect of missalignment: accessing every byte of a 4K buffer
	// will touch one or two pages.

	// Whenever we copy a 4k block, we touch at leat two pages. Source and Destination.
	touchPerBlock := 2.0
	if uintptr(unsafe.Pointer(&buf))&0xFFF != 0 {
		// If not aligned, each 4k copy touches 4 pages
		touchPerBlock = 4.0
		fmt.Printf("TouchPerBlock: %v\n", touchPerBlock)
	}

	touchPerSmallPkt := 2.0
	if uintptr(unsafe.Pointer(&buf))&0xFFF > (4096 - 172) {
		// If a small packet straddles a page boundary we touch 4 pages
		// per copy.
		touchPerSmallPkt = 4.0
		fmt.Printf("TouchPerSmallPkt: %v\n", touchPerSmallPkt)
	}

	// We use various working set sizes and packet sizes to evaluate the costs of L2 TLB and L2
	// cache misses:
	// * L2 TLB size assumed between 1024 (APU2) and 2048 (laptop, CI).
	//   Observed behavior is that performance degrades continuously as the working set size goes
	//   from 1/4 * the TLB size to infinity (as if the replacement policy was purely random). So, we
	//   ensure zero TLB miss only if using 256 pages or less. There also is no specific threshold
	//   for the working set. This is true of Intel and AMD.
	// * L2 Cache size assumed between 2M (laptop, APU2) and 4M (CI). That is 32K to 64K lines.
	//   Observed behaviour is that performance degrades continuously from 2/3 * the cache
	//   size to infinity for Intel, and from 1/2 * the cache size to 1 * the cache size for AMD.
	//   AMD's performance remains constant after that.

	// Test overhead. per loop 1 byte copy. Nothing else.
	_, ohMpps := tc("overhead", 128, 1)

	// Cache: 8*64 = 512 lines. TLB: 8 pages. => per packet: 4K copy. No cache/tlb miss.
	_, ohCpMpps := tc("overhead+copy4k", 8, 4096)

	// Cache: 256*3 = 24 lines. TLB: 8 pages. => per packet: 172b copy. No cache/tlb miss.
	_, ohScMpps := tc("overhead+copy172", 256, 172)

	// Cache: 8K lines. TLB: 8K Pages. => per packet: 1b copy, ~2 TLB miss [P(miss) never exactly 1]
	_, ohTmMpps := tc("overhead+2tlbmiss", 8192, 1)

	// Cache: 256K lines. TLB: 4K pages. => per packet: 4K copy, 2/4 TLB miss, ~128 cache misses.
	_, allMpps := tc("overhead+copy4k+2tlbmiss+128cachemiss", 4096, 4096)

	// Digest this into basic components:
	overheadTimeUs := 1.0 / ohMpps
	mbCopyTimeUs := 1024.0 * 1024.0 * (1.0/ohCpMpps - overheadTimeUs) / 4095.0
	mbShortCopyTimeUs := 1024.0 * 1024.0 * (1.0/ohScMpps - overheadTimeUs) / 171.0
	tlbMissTimeUs := (1.0/ohTmMpps - overheadTimeUs) / 2
	cacheMissTimeUs := (1.0/allMpps - 1.0/ohCpMpps - touchPerBlock*tlbMissTimeUs) / 128

	fmt.Printf("mmbm\": %.4f\n", 1000000.0/mbCopyTimeUs)
	fmt.Printf("mmbm_short\": %.4f\n", 1000000.0/mbShortCopyTimeUs)
	fmt.Printf("mmbm_tlbmiss\": %.4f\n", tlbMissTimeUs)
	fmt.Printf("mmbm_cachemiss\": %.4f\n", cacheMissTimeUs)

	// For shits and giggles, two predictions...

	// Router as configured during the benchmark run: 3549 buffers, 172 bytes packets.
	// Does not fit in TLB. Fits in cache. Number of TLB miss is a function of the number of times
	// the working set exceeds the TLB. In the cases we know, the TLB is 1024. For a working set of
	// N, the probability of TLB miss is (1 - 1024/N).
	//
	// routerPacketTimeUs := 1.0/ohMpps + 1.0/ohScMpps + touchPerSmallPkt*(1-1024/3549)*tlbMissTimeUs
	// fmt.Printf("Predicted router: %.2f MB/s %.2f Mpacket/s\n",
	//	172*1000000.0/(1024*1024.0*routerPacketTimeUs), 1.0/routerPacketTimeUs)
	tc("router", 3549, 172)

	// The same if we had far fewer buffers to churn through.
	tc("routerfast", 256, 172)
}
