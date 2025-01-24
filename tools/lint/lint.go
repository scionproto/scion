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

// Package lint contains helpers for linting and static analysis.
package lint

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"go/types"
	"path"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// FindPackageNames returns all the imported packages mapped to their name in
// the file.
func FindPackageNames(file *ast.File) map[string]string {
	pkgs := map[string]string{}
	for _, imp := range file.Imports {
		pkg := strings.Trim(imp.Path.Value, `"`)
		name := path.Base(pkg)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		pkgs[pkg] = name
	}
	return pkgs
}

// IsString checks if the underlying type of the literal is string.
func IsString(pass *analysis.Pass, lit ast.Expr) bool {
	t, ok := pass.TypesInfo.TypeOf(lit).Underlying().(*types.Basic)
	return ok && t.Info()&types.IsString != 0
}

// RenderList renders the list of expressions.
func RenderList(fset *token.FileSet, list []ast.Expr) string {
	var p []string
	for _, arg := range list {
		p = append(p, Render(fset, arg))
	}
	return fmt.Sprintf("[%s]", strings.Join(p, ","))
}

// Render renders the the expression.
func Render(fset *token.FileSet, x any) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, x); err != nil {
		panic(err)
	}
	return buf.String()
}
