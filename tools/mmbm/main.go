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
)

// Use a pretend working set that ressembles that of a realistic router
// In this case, we use the reference implementation default, which is
// a total of 13.5 * 256 per interface + 3. So, with 3 interfaces in use:
const nbuf = 3459

// For the purpose of performance extrapolation we try to not disadvantage
// hardwares with small caches. So the benchmark has to use a packet size
// that makes the working set fit in 1.2M. However the allocated buffers are 9k
// in size. They just have a long tail that never gets into the cache.
// We mimick that and access only the beginning of the buffers to keep the
// working set below cache size. That is less than 363 bytes. We round to cache line: 320.
const bufSize = 9 * 1024
const cpSize = 320

type oneFrame struct {
	data [cpSize]uint8
	tail [bufSize - cpSize]uint8
}

var buf [nbuf]oneFrame

// Very cheap pseudorandom generator (don't use for anything in serious need
// of randomness).
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
		for j := 0; j < cpSize; j++ {
			buf[i].data[j] = uint8(j % 256)
			buf[i].tail[0] = 0
		}
	}
}

// Copy from a random frame to another random one. This will mostly defeat
// prefetching as the useful portions of the frames are actually far apart.
// The same is happening inside the router.
func BenchmarkCopy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf[random_frame()].data = buf[random_frame()].data
	}
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

	writeBuf()

	res := testing.Benchmark(BenchmarkCopy)
	bytes := uint64(res.N) * cpSize
	megaBytes := float64(bytes) / (1024 * 1024)

	fmt.Printf("\"mmbm\": %.2f\n", megaBytes/res.T.Seconds())
}
