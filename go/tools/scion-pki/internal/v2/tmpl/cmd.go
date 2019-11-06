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

package tmpl

import (
	"io/ioutil"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

var Cmd = &cobra.Command{
	Use:   "tmpl",
	Short: "Generate configuration templates for ISDs and ASes.",
	Long: `
'tmpl' can be used to generate configuration file templates for ISDs and ASes.
`,
}

var topo = &cobra.Command{
	Use:   "topo",
	Short: "Generate isd.ini and as.ini templates for the provided topo",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		val, err := validityFromFlags()
		if err != nil {
			return serrors.WrapStr("invalid validity period", err)
		}
		topo, err := readTopo(args[0])
		if err != nil {
			return serrors.WithCtx(err, "file", args[0])
		}
		g := topoGen{
			Dirs:     pkicmn.GetDirs(),
			Validity: val,
		}
		if err := g.Run(topo); err != nil {
			return serrors.WrapStr("unable to generate templates from topo", err, "file", args[0])
		}
		return nil
	},
}

func init() {
	topo.PersistentFlags().Uint32VarP(&notBefore, "notbefore", "b", 0,
		"set not_before time in all configs")
	topo.PersistentFlags().StringVar(&rawValidity, "validity", "365d",
		"set the validity of all crypto material")
	Cmd.AddCommand(topo)
}

func validityFromFlags() (conf.Validity, error) {
	p, err := util.ParseDuration(rawValidity)
	if err != nil {
		return conf.Validity{}, serrors.WrapStr("invalid validity", err, "input", rawValidity)
	}
	v := conf.Validity{
		NotBefore: notBefore,
		Validity:  util.DurWrap{Duration: p},
	}
	if v.NotBefore == 0 {
		v.NotBefore = util.TimeToSecs(time.Now())
	}
	return v, v.Validate()
}

func readTopo(file string) (topoFile, error) {
	var topo topoFile
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return topo, serrors.WrapStr("unable to read topology file", err)
	}
	if err := yaml.Unmarshal(raw, &topo); err != nil {
		return topo, serrors.WrapStr("unable to parse topology file", err)
	}
	return topo, nil
}
