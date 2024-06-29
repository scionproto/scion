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
//
// The go implementation of memcpy/memmove isn't necessarily the highest performing, but it is close
// to that of glibc's and it has the advantages of being independent from any given libc
// implementation. musl_libc's implementation, for example performs much worse.
//
// The copy speed is strongly influenced by caching effects, tlb effects, and the size of
// the blocks being copied.
// The CPUs available for benchmarking have resisted all attempts at analysing the TLB and
// cache behaviour with any kind of reliability. So we have to be content with collecting some
// empirical data that is relevant to the router benchmark and leave finer grain modeling for later.
//
// Therefore this benchmark measures the speed at which we can copy small packets with a working set
// of a size similar to that of the router, plus a couple of other significant cases in the
// hope that they can be used to make some not-too-incorrrect inferrences.
package main

import (
	"flag"
	"fmt"
	"testing"
)

// The arena that we play with.
const allBufs = 8192
const cycleStep = 5 // Must not divide any working set size, must not be 1.

// Block is a packet buffer representation arranged to make it easy to copy 1, 172 or 4096
// bytes. It is exported to make sure go cannot optimize fields out.
type Block struct {
	page struct {
		packet [172]uint8
		tail   [4096 - 172]uint8
	}
	missalign [64]uint8 //nolint:unused
}

var buf [allBufs]Block

// We arrange to cycle through all the blocks (much like a steady state saturated router would.
// Treat the buffers as a ring, with source and destination on opposite sides. Adjacent buffers
// are used as far apart in time as possible (cycleStep != 1). No buffer is left unused (cycleStep
// not a divisor).
var last int = 0

func nextPair(max int) (int, int) {
	last = (last + max - cycleStep) % max
	return last, (last + max/2) % max
}

// writeBuf: prevents go from taking possible advantage of the buffers being all zero.
// This also allocates the memory pages and primes the cache as if in steady state.
func writeBuf(numBufs int, cpSize int) {
	for i := 0; i < numBufs; i++ {
		for j := 0; j < 172; j++ {
			buf[i].page.packet[j] = uint8(j % 256)
		}
		for j := 172; j < cpSize; j++ {
			buf[i].page.tail[j-172] = uint8(j % 256)
		}
	}
}

// benchmarkCopyByte copies one byte from a block to another
func benchmarkCopyByte(N int, numBufs int) {
	for i := N; i > 0; i-- {
		dst, src := nextPair(numBufs)
		buf[dst].page.packet[0] = buf[src].page.packet[0]
	}
}

// benchmarkCopyPacket copies a short packet from a block to another
func benchmarkCopyPacket(N int, numBufs int) {
	for i := N; i > 0; i-- {
		dst, src := nextPair(numBufs)
		buf[dst].page.packet = buf[src].page.packet
	}
}

// benchmarkCopyBlock copies a large packet from a block to another
func benchmarkCopyBlock(N int, numBufs int) {
	for i := N; i > 0; i-- {
		dst, src := nextPair(numBufs)
		buf[dst].page = buf[src].page
	}
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
			benchmarkCopyByte(b.N, numBufs)
		})
	case 172:
		res = testing.Benchmark(func(b *testing.B) {
			benchmarkCopyPacket(b.N, numBufs)
		})
	case 4096:
		res = testing.Benchmark(func(b *testing.B) {
			benchmarkCopyBlock(b.N, numBufs)
		})
	default:
		panic("Size not supported")
	}
	bytes := uint64(res.N) * uint64(copySize)
	megaBytes := float64(bytes) / (1024 * 1024)

	mbps := megaBytes / res.T.Seconds()
	mpps := float64(res.N) / float64(res.T.Microseconds())

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

	// In the following we assume an L2 TLB size between 1K and 2K, and an L2 cache size
	// of 2M to 4M (32K to 64K lines).

	// Per packet: 172b copy. No misses.
	smallNoMiss, _ := tc("smallNoMiss", 128, 172)

	// Per packet: 172b copy, TLB misses, no cache misses
	// This is the router's default config under the standard benchmark run.
	smallTlbMiss, _ := tc("smallTlbMiss", 3549, 172)

	// "Per packet: 172b copy, Cache misses, no TLB misses" is not feasible.
	// "Per packet, 172b copy, Cache misses, and TLB misses" is not realistic.

	// Per packet: 4k copy. No misses.
	largeNoMiss, _ := tc("largeNoMiss", 128, 4096)

	// "Per packet: 4k copy, TLB misses, no cache misses" is not feasible.

	// Per packet: 4k copy, Cache misses, no TLB misses
	// (Works unless we have a CPU with the smallest TLB and the largeest cache).
	largeCacheMiss, _ := tc("largeCacheMiss", 1024, 4096)

	// Per packet, 4k copy, Cache misses, and TLB misses
	largeAllMiss, _ := tc("largeAllMiss", 3071, 4096)

	// All the results here. Best avoid printfs before. It tickles the gc.

	fmt.Printf("\"mmbm\": %.2f,\n", smallTlbMiss) // Look at this one by default

	fmt.Printf("\"mmbm_small_no_miss\": %.2f,\n", smallNoMiss)
	fmt.Printf("\"mmbm_small_tlbmiss\": %.2f,\n", smallTlbMiss)
	fmt.Printf("\"mmbm_large_no_miss\": %.2f,\n", largeNoMiss)
	fmt.Printf("\"mmbm_large_cachemiss\": %.2f,\n", largeCacheMiss)
	fmt.Printf("\"mmbm_large_allmiss\": %.2f\n", largeAllMiss)
}
