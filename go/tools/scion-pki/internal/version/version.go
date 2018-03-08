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

package version

import (
	"fmt"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
)

const (
	major = 0
	minor = 1
)

var CmdVersion = &base.Command{
	Name:      "version",
	Run:       runVersion,
	UsageLine: "version",
	Short:     "Print scion-pki version",
	Long:      "Print scion-pki version",
}

func runVersion(cmd *base.Command, args []string) {
	if len(args) != 0 {
		cmd.Usage()
	}
	fmt.Printf("SCION Control Plane PKI tool v%d.%d\n", major, minor)
}
