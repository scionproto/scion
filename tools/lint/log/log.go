// Copyright 2019 Anapaya Systems
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

package log

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Analyzer contains an analyzer that makes sure that go target is always a
// func literal that calls defer log.HandlePanic as first statement.
var Analyzer = &analysis.Analyzer{
	Name: "gocall",
	Doc: "go target is a func that calls" +
		" defer log.HandlePanic as first statement",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

var goCallFilter = []ast.Node{
	(*ast.GoStmt)(nil),
}

func run(pass *analysis.Pass) (any, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	inspect.Preorder(goCallFilter, func(n ast.Node) {
		goStmt := n.(*ast.GoStmt)
		call := goStmt.Call
		switch f := call.Fun.(type) {
		case *ast.FuncLit:
			if !checkFuncLit(pass, f) {
				pass.Reportf(f.Pos(), "First statement should be 'defer HandlePanic()")
			}
		default:
			pass.Reportf(f.Pos(), "go statement should always call a func lit.")
		}
	})
	return nil, nil
}

func checkFuncLit(pass *analysis.Pass, fl *ast.FuncLit) bool {
	if len(fl.Body.List) == 0 {
		return true
	}
	firstStmt := fl.Body.List[0]
	deferStmt, ok := firstStmt.(*ast.DeferStmt)
	if !ok {
		return false
	}
	if pkgNameSave(pass) == "log" {
		ident, ok := deferStmt.Call.Fun.(*ast.Ident)
		if !ok || ident.Name != "HandlePanic" {
			return false
		}
	} else {
		callSel, ok := deferStmt.Call.Fun.(*ast.SelectorExpr)
		if !ok || callSel.Sel.Name != "HandlePanic" {
			return false
		}
	}
	return true
}

func pkgNameSave(pass *analysis.Pass) string {
	if pass.Pkg != nil {
		return pass.Pkg.Name()
	}
	return ""
}
