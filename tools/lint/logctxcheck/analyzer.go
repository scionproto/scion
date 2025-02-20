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
	"fmt"
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"

	"github.com/scionproto/scion/tools/lint"
)

var importPath = "github.com/scionproto/scion/pkg/log"

// Analyzer checks all calls on the log package.
var Analyzer = &analysis.Analyzer{
	Name:             "logctxcheck",
	Doc:              "reports invalid log calls",
	Run:              run,
	RunDespiteErrors: true,
}

func run(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		if _, ok := lint.FindPackageNames(file)[importPath]; !ok {
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

			if !isTarget(pass, se) {
				return true
			}
			var varargs []ast.Expr
			switch se.Sel.Name {
			case "Debug", "Info", "Error":
				if len(ce.Args) < 2 {
					return true
				}
				varargs = ce.Args[1:]
			case "New":
				varargs = ce.Args
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
			seen := map[string]bool{}
			for i := 0; i < len(varargs); i += 2 {
				lit := varargs[i]
				k := litKey(lit)
				if !seen[k] {
					seen[k] = true
					continue
				}
				pass.Reportf(
					lit.Pos(),
					"duplicate key in context: name=%q expr=%q",
					lint.Render(pass.Fset, lit),
					lint.Render(pass.Fset, ce),
				)
			}
			return true
		})
	}
	return nil, nil
}

func isTarget(pass *analysis.Pass, se *ast.SelectorExpr) bool {
	pkgIdent, _ := se.X.(*ast.Ident)
	pkgName, ok := pass.TypesInfo.Uses[pkgIdent].(*types.PkgName)
	if ok && pkgName.Imported().Path() == importPath {
		return true
	}
	if typ := pass.TypesInfo.TypeOf(se.X); typ != nil {
		return typ.String() == importPath+".Logger"
	}
	return false
}

func litKey(lit ast.Expr) string {
	switch v := lit.(type) {
	case *ast.BasicLit:
		return v.Value
	case *ast.Ident:
		return v.Name
	default:
		return fmt.Sprint(lit)
	}
}
