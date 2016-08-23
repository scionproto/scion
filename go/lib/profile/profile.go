// Copyright 2016 ETH Zurich
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

package profile

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
)

var cpuF, memF *os.File

func Start(name string) {
	startCpu(name)
	startMem(name)
}

func startCpu(name string) {
	var err error
	path := fmt.Sprintf("%s.cpu.pprof", name)
	cpuF, err = os.Create(path)
	if err != nil {
		panic(fmt.Sprintf("Could not create CPU profile: %v", err))
	}
	if err := pprof.StartCPUProfile(cpuF); err != nil {
		panic(fmt.Sprintf("Could not start CPU profile: %v", err))
	}
	fmt.Printf("CPU profiling to %v\n", path)
}

func startMem(name string) {
	var err error
	path := fmt.Sprintf("%s.mem.pprof", name)
	memF, err = os.Create(path)
	if err != nil {
		panic(fmt.Sprintf("Could not create Mem profile: %v", err))
	}
	fmt.Printf("Mem profiling enabled (rate %d)\n", runtime.MemProfileRate)
}

func Stop() {
	if cpuF != nil {
		pprof.StopCPUProfile()
		cpuF.Close()
		fmt.Printf("CPU profiling stopped\n")
	}
	if memF != nil {
		runtime.GC()
		if err := pprof.WriteHeapProfile(memF); err != nil {
			panic(fmt.Sprintf("Could not write memory profile: %v", err))
		}
		memF.Close()
		fmt.Printf("Mem profiling stopped\n")
	}
}
