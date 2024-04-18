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
// The copy speed is strongly influenced by caching effects, tlb effects, and the size of
// the blocks being copied. This benchmark outputs several observations.
// mmbm_page: MB/s copy rate for a 4096 bytes block is copied, assuming no TLB nor cache misses.
// mmbm_short: MB/s copy rate for a 172 bytes block is copied, assuming no TLB nor cache misses.
// mmbm_tlbmiss: The cost (in microsecond) of a TLB miss.
// mmbm_cachemiss: The cost (in microsecond) of a cache miss.
// mmbm: The average MB/s copy rate assuming a certain rate of TLB misses (can be used for a
//
//	limited performance predictor).
package main

import (
	"flag"
	"fmt"
	"math"
	"testing"
	"unsafe"
)

// The arena that we play with.
const allBufs = 8192
const bufSize = 4096
const cycleStep = 3 // Must not divide allBuffs, must not be 1.

// Block is a packet buffer representation arranged to make it easy to copy 1, 172 or 4k bytes.
// It is exported to prevent go from optimizing fields out.
type Block struct {
	packet struct {
		oneByte uint8
		theRest [171]uint8
	}
	tail [bufSize - 172]uint8
}

var buf [allBufs]Block

// We arrange to cycle through all the blocks (much like a steady state saturated router would need
// to). Treat the buffers as a ring, with source and destination on opposite sides. Adjacent buffers
// are used as far appart in time as possible (cycleStep != 1). No buffer is left unused (cycleStep
// not a divisor).
var last int = 0

func nextPair(max int) (int, int) {
	last = (last + max - cycleStep) % max
	return last, (last + max/2) % max
}

// writeBuf: prevents go from taking possible advantage of the buffers being all zero.
// This also allocates the memory pages and get everything we do not touch  out of the cache (and
// some or all of what we touch in it).
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

// benchmarkCopyByte copies one byte from a block to another
func benchmarkCopyByte(b *testing.B, numBufs int, copySize int) {
	for i := 0; i < b.N; i++ {
		dst, src := nextPair(numBufs)
		buf[dst].packet.oneByte = buf[src].packet.oneByte
	}
	return
}

// benchmarkCopyPacket copies a short packet from a block to another
func benchmarkCopyPacket(b *testing.B, numBufs int, copySize int) {
	for i := 0; i < b.N; i++ {
		dst, src := nextPair(numBufs)
		buf[dst].packet = buf[src].packet
	}
	return
}

// benchmarkCopyBlock copies a short packet from a block to another
func benchmarkCopyBlock(b *testing.B, numBufs int, copySize int) {
	for i := 0; i < b.N; i++ {
		dst, src := nextPair(numBufs)
		buf[dst] = buf[src]
	}
	return
}

// tc benchmarks one type of copy or another depending on the requested copySize and
// using a working set of numBuf blocks. It returns a number of mebi bytes per second and
// a number of million packets per second.
func tc(name string, numBufs int, copySize int) (float64, float64) {
	var res testing.BenchmarkResult
	writeBuf(numBufs, copySize)
	switch copySize {
	case 1:
		res = testing.Benchmark(func(b *testing.B) {
			benchmarkCopyByte(b, numBufs, copySize)
		})
	case 172:
		res = testing.Benchmark(func(b *testing.B) {
			benchmarkCopyPacket(b, numBufs, copySize)
		})
	case 4096:
		res = testing.Benchmark(func(b *testing.B) {
			benchmarkCopyBlock(b, numBufs, copySize)
		})
	default:
		panic("Size not supported")
	}
	bytes := uint64(res.N) * uint64(copySize)
	megaBytes := float64(bytes) / (1024 * 1024)

	mbps := megaBytes / res.T.Seconds()
	mpps := float64(res.N) / float64(res.T.Microseconds())

	// fmt.Printf("%s (%d, %d): %.2f MB/s %.2f Mpacket/s\n", name, numBufs, copySize, mbps, mpps)

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
	}

	// We use various working set sizes and packet sizes to evaluate the costs of L2 TLB and L2
	// cache misses:
	// * L2 TLB size assumed between 512 (APU2) and 2048 (laptop, CI).
	//   Observed behavior is that performance degrades continuously as the working set size goes
	//   from 1/4 * the TLB size to infinity (as if the replacement policy was purely random). So,
	//   we ensure zero TLB miss only if using 128 pages or less. There also is no specific
	//   threshold for the working set. This is true of Intel and AMD.
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

	fmt.Printf("\"mmbm_page\": %.2f,\n", 1000000.0/mbCopyTimeUs)
	fmt.Printf("\"mmbm_short\": %.2f,\n", 1000000.0/mbShortCopyTimeUs)
	fmt.Printf("\"mmbm_tlbmiss\": %.4f,\n", tlbMissTimeUs)
	fmt.Printf("\"mmbm_cachemiss\": %.4f,\n", cacheMissTimeUs)

	// Directly observe the aggregate copy speed of small packets (per our 172 bytes measurement)
	// for a router with a working set similar to the reference impl (that is 3549 buffers). Note
	// that on APU2 this is much worse than any of the predictions. It may well be that the APU2 TLB
	// is actually 1024 as claimed but that the performance is low for another yet to be determined
	// reason.
	observedSmallCopyRate, _ := tc("small_packets", 3549, 172)

	// While we're at it, use this to guess the TLB size.
	// Each copy incurs the base overhead, the short copy time, and 2 * the TLB miss average. No
	// cache miss. The TLB miss average is a TLB miss time multiplied by the miss probability:
	// roughly (1 - S/W) where W is the working set and S the TLB size. We predict 2 * miss rate
	// because the probability that a small packet straddles a page boundary is small.
	pMiss512TLB := 1.0 - 512.0/3549.0
	pMiss1kTLB := 1.0 - 1024.0/3549.0
	pMiss2kTLB := 1.0 - 2048.0/3549.0

	smallPktTimeUs := 1.0/ohScMpps + 2.0*pMiss512TLB*tlbMissTimeUs
	predictedMmbm512 := 172 * 1000000.0 / (1024 * 1024.0 * smallPktTimeUs)

	smallPktTimeUs = 1.0/ohScMpps + 2.0*pMiss1kTLB*tlbMissTimeUs
	predictedMmbm1k := 172 * 1000000.0 / (1024 * 1024.0 * smallPktTimeUs)

	smallPktTimeUs = 1.0/ohScMpps + 2.0*pMiss2kTLB*tlbMissTimeUs
	predictedMmbm2k := 172 * 1000000.0 / (1024 * 1024.0 * smallPktTimeUs)

	tlb_sz := 512
	closest := math.Abs(predictedMmbm512 - observedSmallCopyRate)

	if math.Abs(predictedMmbm1k-observedSmallCopyRate) < closest {
		tlb_sz = 1024
		closest = math.Abs(predictedMmbm1k - observedSmallCopyRate)
	}
	if math.Abs(predictedMmbm2k-observedSmallCopyRate) < closest {
		tlb_sz = 2048
	}
	fmt.Printf("\"mmbm_tlbsize\": %d\n", tlb_sz)

	// Output the observed mmbm rate. This can be used for a simplistic predictor at the expanse
	// of being too tied to our specific router implementation, but it'll have to do until we can
	// devise more sophisticated predictors using the other data that we output.
	fmt.Printf("\"mmbm\": %.2f\n", observedSmallCopyRate)
}
