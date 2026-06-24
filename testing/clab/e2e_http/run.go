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
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func runCmd() *cobra.Command {
	var (
		genDir   string
		lab      string
		dockerC  string
		bin      string
		port     int
		parallel int
		startup  time.Duration
		duration time.Duration
		timeout  time.Duration
		cmdTO    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Drive the HTTP/3-over-SCION test across all AS pairs",
		Long: `Discover the generated containerlab lab, start an HTTP/3 server in every
AS node (via docker exec), then fetch from every server out of every other AS
node and report a condensed source×destination result matrix.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d := driver{
				docker: docker{cmd: dockerC}, bin: bin, port: port,
				parallel: parallel, duration: duration, clientTO: timeout, cmdTO: cmdTO,
			}
			ok, err := d.run(genDir, lab, startup)
			if err != nil {
				return err
			}
			if !ok {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&genDir, "gen", "gen", "testgen output directory")
	cmd.Flags().StringVar(&lab, "lab", "scion", "containerlab lab name")
	cmd.Flags().StringVar(&dockerC, "docker", "docker", "docker command (e.g. \"sudo docker\")")
	cmd.Flags().StringVar(&bin, "bin", "/app/e2e_http", "path of this binary inside the node")
	cmd.Flags().IntVar(&port, "port", 40000, "SCION/UDP port the servers listen on")
	cmd.Flags().IntVar(&parallel, "parallel", 16, "maximum concurrent client probes")
	cmd.Flags().DurationVar(&startup, "startup", 3*time.Second, "wait for servers to come up")
	cmd.Flags().DurationVar(&duration, "server-duration", 120*time.Second,
		"how long the servers run before self-terminating")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "per-request client timeout")
	cmd.Flags().DurationVar(&cmdTO, "cmd-timeout", 30*time.Second, "per-command wall-clock timeout")
	return cmd
}

// docker runs commands inside containerlab node containers.
type docker struct{ cmd string }

func (d docker) argv(args ...string) (string, []string) {
	fields := strings.Fields(d.cmd)
	return fields[0], append(fields[1:], args...)
}

type driver struct {
	docker   docker
	bin      string
	port     int
	parallel int
	duration time.Duration
	clientTO time.Duration
	cmdTO    time.Duration
}

func (d driver) run(genDir, lab string, startup time.Duration) (bool, error) {
	eps, err := loadEndpoints(genDir, lab)
	if err != nil {
		return false, err
	}
	if len(eps) < 2 {
		return false, fmt.Errorf("need at least 2 ASes, found %d", len(eps))
	}
	fmt.Printf("lab %q: %d ASes, port %d, parallelism %d\n", lab, len(eps), d.port, d.parallel)

	// Start one server per AS (detached, self-terminating after the duration).
	fmt.Println("starting servers ...")
	for _, ep := range eps {
		bin, args := d.docker.argv("exec", "-d", ep.Container, d.bin, "server",
			"--sciond", ep.sciondAddr(),
			"--listen", ep.listenAddr(d.port),
			"--duration", d.duration.String())
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			return false, fmt.Errorf("starting server in %s: %w: %s", ep.Container, err, out)
		}
	}
	time.Sleep(startup)

	// Client probe for every ordered pair of distinct ASes.
	var jobs []job
	for _, src := range eps {
		for _, dst := range eps {
			if src.IA == dst.IA {
				continue
			}
			jobs = append(jobs, job{src: src, dst: dst})
		}
	}
	fmt.Printf("running %d client probes ...\n", len(jobs))
	results := d.runJobs(jobs)
	return report(eps, results), nil
}

// job is a single client probe from src to dst.
type job struct{ src, dst endpoint }

// result is the outcome of a probe.
type result struct {
	src, dst endpoint
	err      error
	output   string
}

func (d driver) runJobs(jobs []job) []result {
	results := make([]result, len(jobs))
	sem := make(chan struct{}, d.parallel)
	var wg sync.WaitGroup
	var done int64
	stop := startProgress(&done, len(jobs))

	for i := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = d.probe(jobs[i])
			atomic.AddInt64(&done, 1)
		}(i)
	}
	wg.Wait()
	stop()
	return results
}

func (d driver) probe(j job) result {
	ctx, cancel := context.WithTimeout(context.Background(), d.cmdTO)
	defer cancel()

	bin, args := d.docker.argv("exec", j.src.Container, d.bin, "client",
		"--sciond", j.src.sciondAddr(),
		"--remote", j.dst.remoteAddr(d.port),
		"--timeout", d.clientTO.String())
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	return result{src: j.src, dst: j.dst, err: err, output: string(out)}
}

// report prints a condensed source×destination matrix, a summary, and the
// details of any failures. It returns true if every probe succeeded.
func report(eps []endpoint, results []result) bool {
	idx := make(map[string]int, len(eps))
	for i, e := range eps {
		idx[e.IA] = i + 1
	}
	byPair := make(map[[2]string]result, len(results))
	var fails []result
	passed := 0
	for _, r := range results {
		byPair[[2]string{r.src.IA, r.dst.IA}] = r
		if r.err == nil {
			passed++
		} else {
			fails = append(fails, r)
		}
	}

	fmt.Printf("\nhttp3: %d/%d ok\n", passed, len(results))
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	header := []string{"  src \\ dst"}
	for i := range eps {
		header = append(header, fmt.Sprint(i+1))
	}
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, src := range eps {
		row := []string{fmt.Sprintf("%d %s", idx[src.IA], src.IA)}
		for _, dst := range eps {
			switch {
			case src.IA == dst.IA:
				row = append(row, "·")
			case byPair[[2]string{src.IA, dst.IA}].err == nil:
				row = append(row, "✓")
			default:
				row = append(row, "✗")
			}
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()

	if len(fails) > 0 {
		sort.Slice(fails, func(i, j int) bool {
			if fails[i].src.IA != fails[j].src.IA {
				return fails[i].src.IA < fails[j].src.IA
			}
			return fails[i].dst.IA < fails[j].dst.IA
		})
		fmt.Printf("  failures:\n")
		for _, r := range fails {
			fmt.Printf("    %s -> %s: %s\n", r.src.IA, r.dst.IA, firstLine(r.output))
		}
	}
	return len(fails) == 0
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func startProgress(done *int64, total int) func() {
	if info, err := os.Stderr.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return func() {}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	finished := make(chan struct{})
	go func() {
		render := func(n int) {
			const width = 30
			filled, pct := 0, 0
			if total > 0 {
				filled = n * width / total
				pct = n * 100 / total
			}
			bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
			fmt.Fprintf(os.Stderr, "\r[%s] %d/%d (%d%%)", bar, n, total, pct)
		}
		for {
			select {
			case <-ticker.C:
				render(int(atomic.LoadInt64(done)))
			case <-finished:
				render(total)
				fmt.Fprintln(os.Stderr)
				return
			}
		}
	}()
	return func() {
		ticker.Stop()
		close(finished)
	}
}
