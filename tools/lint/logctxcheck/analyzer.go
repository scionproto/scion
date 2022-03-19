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

package logctxcheck

import (
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/analysis"

	"github.com/scionproto/scion/tools/lint"
)

// Analyzer checks all calls on the log package.
var Analyzer = &analysis.Analyzer{
	Name:             "logctxcheck",
	Doc:              "reports invalid log calls",
	Run:              run,
	RunDespiteErrors: true,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		tgtPkg, ok := lint.FindPackageNames(file)["github.com/scionproto/scion/pkg/log"]
		if !ok {
			continue
		}

		ast.Inspect(file, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			se, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if !isTarget(se, tgtPkg) {
				return true
			}
			var varargs []ast.Expr
			switch se.Sel.Name {
			case "Debug", "Info", "Warn", "Error", "Crit":
				if len(ce.Args) < 2 {
					return true
				}
				varargs = ce.Args[1:]
			}
			// We cannot check if varargs with ellipsis.
			if ce.Ellipsis != token.NoPos {
				return true
			}
			if len(varargs)%2 != 0 {
				pass.Reportf(
					varargs[0].Pos(),
					"context should be even: len=%d ctx=%s expr=%q",
					len(varargs),
					lint.RenderList(pass.Fset, varargs),
					lint.Render(pass.Fset, ce),
				)
			}
			for i := 0; i < len(varargs); i += 2 {
				lit := varargs[i]
				if lint.IsString(pass, lit) {
					continue
				}
				pass.Reportf(
					lit.Pos(),
					"key should be string: type=%q name=%q expr=%q",
					pass.TypesInfo.TypeOf(lit),
					lint.Render(pass.Fset, lit),
					lint.Render(pass.Fset, ce),
				)
			}
			return true
		})
	}
	return nil, nil
}

func isTarget(se *ast.SelectorExpr, tgtPkg string) bool {
	switch x := se.X.(type) {
	case *ast.Ident:
		if x.Name == tgtPkg && x.Obj == nil {
			return true
		}
		if x.Obj == nil {
			return false
		}
		decl, ok := x.Obj.Decl.(*ast.AssignStmt)
		if !ok {
			return false
		}
		for _, data := range decl.Rhs {
			if loggerConstructor(data, tgtPkg) {
				return true
			}
		}
		return false
	case *ast.CallExpr:
		return loggerConstructor(x, tgtPkg)
	default:
		return false
	}
}

func loggerConstructor(exp ast.Expr, tgtPkg string) bool {
	ce, ok := exp.(*ast.CallExpr)
	if !ok {
		return false
	}
	se, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := se.X.(*ast.Ident)
	if !ok {
		return false
	}
	if id.Name != tgtPkg {
		return false
	}
	switch se.Sel.Name {
	case "FromCtx", "New", "Root":
		return true
	}
	return false
}
