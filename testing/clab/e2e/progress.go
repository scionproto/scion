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

package e2e

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// StartProgress renders a live progress bar to stderr (only on a terminal),
// driven by the done counter, and returns a stop function that finalizes it.
func StartProgress(done *int64, total int) func() {
	if !isTerminal(os.Stderr) {
		return func() {}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	finished := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				renderBar(int(atomic.LoadInt64(done)), total)
			case <-finished:
				renderBar(total, total)
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

func renderBar(done, total int) {
	const width = 30
	filled, pct := 0, 0
	if total > 0 {
		filled = done * width / total
		pct = done * 100 / total
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	fmt.Fprintf(os.Stderr, "\r[%s] %d/%d (%d%%)", bar, done, total, pct)
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
