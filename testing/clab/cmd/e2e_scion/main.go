// Copyright 2026 Anapaya Systems
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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/testing/clab/e2e"
)

func main() {
	os.Exit(run())
}

var (
	genDir     = flag.String("gen", "gen", "testgen output directory")
	lab        = flag.String("lab", "scion", "containerlab lab name")
	dockerCmd  = flag.String("docker", "docker", "docker command (e.g. \"sudo docker\")")
	scionBin   = flag.String("scion", "/app/scion", "path of the scion CLI inside the node")
	testFilter = flag.String("test", "all", "test to run: ping | showpaths | all")
	count      = flag.Int("count", 1, "number of ping packets")
	pingTO     = flag.Duration("timeout", 4*time.Second, "per-probe scion timeout")
	cmdTO      = flag.Duration("cmd-timeout", 30*time.Second, "per-command wall-clock timeout")
	parallel   = flag.Int("parallel", 64, "maximum number of probes to run concurrently")
)

// testKind describes one kind of probe and how to build/check it.
type testKind struct {
	name string
	args func(src, dst e2e.Endpoint) []string
	// check validates the command output; nil means exit code only.
	check func(string) error
}

func kinds() []testKind {
	return []testKind{
		{
			name: "ping",
			args: func(src, dst e2e.Endpoint) []string {
				return []string{"ping", "-c", fmt.Sprint(*count), dst.SCIONAddr(),
					"--sciond", src.SciondAddr(), "--timeout", pingTO.String()}
			},
		},
		{
			name: "showpaths",
			args: func(src, dst e2e.Endpoint) []string {
				return []string{"showpaths", dst.IA, "--sciond", src.SciondAddr(),
					"--timeout", pingTO.String()}
			},
			check: func(out string) error {
				if strings.Contains(out, "alive") {
					return nil
				}
				return fmt.Errorf("no alive path")
			},
		},
	}
}

// job is a single probe to run.
type job struct {
	kind     testKind
	src, dst e2e.Endpoint
}

// result is the outcome of a job.
type result struct {
	job    job
	ok     bool
	err    error
	output string
}

func run() int {
	flag.Parse()

	eps, err := e2e.LoadEndpoints(*genDir, *lab)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	if len(eps) < 2 {
		fmt.Fprintf(os.Stderr, "Error: need at least 2 ASes, found %d\n", len(eps))
		return 1
	}

	// Build the job list: every selected test for every ordered pair of
	// distinct ASes.
	var jobs []job
	for _, k := range kinds() {
		if *testFilter != "all" && *testFilter != k.name {
			continue
		}
		for _, src := range eps {
			for _, dst := range eps {
				if src.IA != dst.IA {
					jobs = append(jobs, job{kind: k, src: src, dst: dst})
				}
			}
		}
	}
	if len(jobs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no tests selected (test=%q)\n", *testFilter)
		return 1
	}
	fmt.Printf("lab %q: %d ASes, %d probes, parallelism %d\n",
		*lab, len(eps), len(jobs), *parallel)

	results := runJobs(jobs)
	report(eps, results)

	for _, r := range results {
		if !r.ok {
			return 1
		}
	}
	return 0
}

// runJobs runs all jobs concurrently, bounded by a semaphore, while rendering a
// progress bar. Results are returned in job order.
func runJobs(jobs []job) []result {
	results := make([]result, len(jobs))
	sem := make(chan struct{}, *parallel)
	var wg sync.WaitGroup
	var done int64

	stop := e2e.StartProgress(&done, len(jobs))

	for i := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = probe(jobs[i])
			atomic.AddInt64(&done, 1)
		}(i)
	}
	wg.Wait()
	stop()
	return results
}

// probe runs a single job's scion command inside the source container.
func probe(j job) result {
	ctx, cancel := context.WithTimeout(context.Background(), *cmdTO)
	defer cancel()

	docker := e2e.Docker{Cmd: *dockerCmd}
	bin, argv := docker.Exec(j.src.Container, *scionBin, j.kind.args(j.src, j.dst)...)
	out, err := exec.CommandContext(ctx, bin, argv...).CombinedOutput()

	r := result{job: j, output: string(out)}
	switch {
	case err != nil:
		r.err = err
	case j.kind.check != nil:
		r.err = j.kind.check(string(out))
	}
	r.ok = r.err == nil
	return r
}

// report prints, per test, a condensed source×destination result matrix
// (sorted by ISD-AS), a summary line, and the details of any failures.
func report(eps []e2e.Endpoint, results []result) {
	byKind := map[string]map[[2]string]result{}
	order := []string{}
	for _, r := range results {
		m, ok := byKind[r.job.kind.name]
		if !ok {
			m = map[[2]string]result{}
			byKind[r.job.kind.name] = m
			order = append(order, r.job.kind.name)
		}
		m[[2]string{r.job.src.IA, r.job.dst.IA}] = r
	}

	for _, name := range order {
		m := byKind[name]
		var fails []result
		passed := 0
		for _, r := range m {
			if r.ok {
				passed++
			} else {
				fails = append(fails, r)
			}
		}

		fmt.Printf("\n%s: %d/%d ok\n", name, passed, len(m))
		e2e.PrintMatrix(eps, func(src, dst e2e.Endpoint) bool {
			return m[[2]string{src.IA, dst.IA}].ok
		})

		if len(fails) > 0 {
			sort.Slice(fails, func(i, j int) bool {
				if fails[i].job.src.IA != fails[j].job.src.IA {
					return fails[i].job.src.IA < fails[j].job.src.IA
				}
				return fails[i].job.dst.IA < fails[j].job.dst.IA
			})
			fmt.Printf("  failures:\n")
			for _, r := range fails {
				fmt.Printf("    %s -> %s: %s\n", r.job.src.IA, r.job.dst.IA, r.err)
			}
		}
	}
}
