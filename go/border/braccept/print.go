// Copyright 2018 ETH Zurich
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
	"fmt"
	"os"

	"github.com/kormat/fmt15"
	"github.com/mattn/go-isatty"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var colorTerm = isatty.IsTerminal(os.Stdout.Fd())

func StringDiffPrettyPrint(actStr, expStr string) string {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(actStr, expStr, false)
	if colorTerm {
		var actDiff []diffmatchpatch.Diff
		for i := range diffs {
			// remove DiffInsert types, so it only shows DiffDeletes
			if diffs[i].Type != diffmatchpatch.DiffInsert {
				actDiff = append(actDiff, diffs[i])
			}
		}
		actStr = dmp.DiffPrettyText(actDiff)
		var expDiff []diffmatchpatch.Diff
		for i := range diffs {
			// remove DiffInsert types, so it only shows DiffDeletes
			if diffs[i].Type != diffmatchpatch.DiffDelete {
				expDiff = append(expDiff, diffs[i])
			}
		}
		expStr = dmp.DiffPrettyText(expDiff)
	}
	return fmt.Sprintf("Expected: %s\nActual:   %s\n", expStr, actStr)
}

const (
	passUni = "\u2714"
	failUni = "\u2715"
	green   = 32
	red     = 31
)

func pass() string {
	if colorTerm {
		return fmt15.ColorStr(passUni, green)
	}
	return "PASS"
}

func fail() string {
	if colorTerm {
		return fmt15.ColorStr(failUni, red)
	}
	return "FAIL"
}
