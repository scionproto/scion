// Copyright 2022 Anapaya Systems
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

package maincheck

import (
	"go/ast"
	"path/filepath"

	"golang.org/x/tools/go/analysis"
)

var permitted = []string{
	"main.go",
	"testmain.go",                    // bazel uses this for unit and integration tests.
	"go_default_mock_gomock_prog.go", // bazel uses this for mock generation.
}

// Analyzer contains an analyzer that makes sure that go target is always a
// func literal that calls defer log.HandlePanic as first statement.
var Analyzer = &analysis.Analyzer{
	Name:             "maincheck",
	Doc:              "Check that main function is located in a main.go file",
	Run:              run,
	RunDespiteErrors: true,
}

func run(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		// If this is not a main package, we can exit early.
		if file.Name.Name != "main" {
			return nil, nil
		}

		for _, dec := range file.Decls {
			fun, ok := dec.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fun.Name.Name != "main" {
				continue
			}
			base := filepath.Base(pass.Fset.File(file.Name.NamePos).Name())
			found := func() bool {
				for _, p := range permitted {
					if base == p {
						return true
					}
				}
				return false
			}()

			if !found {
				pass.Reportf(fun.Pos(),
					"main function must be located in a file called main.go instead of %s", base,
				)
			}
		}
	}
	return nil, nil
}
