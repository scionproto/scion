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
package main

import (
	"flag"
	"fmt"
	"testing"
)

// Use a pretend working set that ressembles that of a realistic router
// In this case, we use the reference implementation default, which is
// a total of 13.5 * 256 per interface + 3. So
const nbuf = 3459

// For the purpose of performance extrapolation we try to not disadvantage
// hardwares with small caches. So the benchmark has to use a packet size
// that makes the working set fit in 1.2M. That is less than 363 bytes. Round
// it down to a common 64 byte cache line multiple: 320
// TODO(jiceatscion): So, for now, the whole benchmark is restricted to measuring
// and predicting an ideal 100% in-cache performance. In the future, we will
// extend the model to multiple caching circumstances and execute this benchmark with
// different cache size targets.
const frameSize = 320

type oneFrame [frameSize]uint8

var buf [nbuf]oneFrame

// Very cheap pseudorandom generator (don't use for anything in serious need
// of randomness.
const some_prime = 2297

var last int = 0

func random_frame() int {
	last = (last + some_prime) % nbuf
	return last
}

// Just in case Go would take advantage of the initial zero value, somehow.
// This also allocates the memory pages.
func writeBuf() {
	for i := 0; i < nbuf; i++ {
		for j := 0; j < frameSize; j++ {
			buf[i][j] = uint8(j % 256)
		}
	}
}

// Copy from a random frame to another random one. This will mostly defeat
// caching and prefetching, but not strictly always. Pretty much like in
// a real scenario.
func BenchmarkCopy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf[random_frame()] = buf[random_frame()]
	}
}

func main() {
	testing.Init()
	flag.VisitAll(func(f *flag.Flag) {
		if f.Name == "test.benchtime" {
			err := f.Value.Set("2s") // More than enough, but 1s can be too short.
			if err != nil {
				panic(err)
			}
		}
	})

	writeBuf()

	res := testing.Benchmark(BenchmarkCopy)
	bytes := uint64(res.N) * frameSize
	megaBytes := float64(bytes) / (1024 * 1024)

	fmt.Printf("\"mmbm\": %.2f\n", megaBytes/res.T.Seconds())
}
