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

// Spread the load over many buffers to defeat caching.
const nbuf = 4096

// Copy by batches of typical jumbo frame
const cpsz = 8192

type oneFrame [cpsz]uint8

var buf1 [nbuf]oneFrame
var buf2 [nbuf]oneFrame

// Just in case Go would take advantage of the initial zero value
func writeBuf1() {
	for i := 0; i < nbuf; i++ {
		for j := 0; j < cpsz; j++ {
			buf1[i][j] = uint8(j % 256)
		}
	}
}

func BenchmarkCopy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		n := i % nbuf
		buf1[n] = buf2[n]
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

	writeBuf1()

	res := testing.Benchmark(BenchmarkCopy)
	bytes := uint64(res.N) * cpsz
	megaBytes := float64(bytes) / (1024 * 1024)

	fmt.Printf("\"mmbm\": %.2f\n", megaBytes/res.T.Seconds())
}
