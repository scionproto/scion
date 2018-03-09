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

package base

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/template"
)

type Command struct {
	// Name is the name of the command.
	Name string
	// Run runs the command. The args are the arguments after the command name.
	Run func(cmd *Command, args []string)
	// UsageLine is the one-line usage message.
	UsageLine string
	// Short is the short description in the help output.
	Short string
	// Long is the long description in the help output.
	Long string
	// Flag is the set of flags specific to this command.
	Flag flag.FlagSet
}

// Commands contains the available commands.
var Commands []*Command

func (c *Command) Usage() {
	fmt.Fprintf(os.Stderr, "usage: scion-pki %s\n", c.UsageLine)
	fmt.Fprintf(os.Stderr, "Run 'scion-pki help %s' for details.\n", c.Name)
	os.Exit(2)
}

func (c *Command) Help() {
	Tmpl(helpTemplate, c)
}

var helpTemplate = `usage: scion-pki {{.UsageLine}}

{{.Long | trim}}
`

// tmpl executes the given template text on data, writing the result to stdout.
func Tmpl(text string, data interface{}) {
	t := template.New("top")
	t.Funcs(template.FuncMap{"trim": strings.TrimSpace})
	template.Must(t.Parse(text))
	if err := t.Execute(os.Stdout, data); err != nil {
		panic(err)
	}
}

func ErrorAndExit(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(2)
}
