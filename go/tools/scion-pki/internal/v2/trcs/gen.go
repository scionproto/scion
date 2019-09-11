// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package trcs

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

func runGenTrc(selector string) error {
	asMap, err := pkicmn.ProcessSelector(selector)
	if err != nil {
		return err
	}
	for isd := range asMap {
		if err = genAndWriteSignedTRC(isd); err != nil {
			return common.NewBasicError("unable to generate TRC", err, "isd", isd)
		}
	}
	return nil
}

func genAndWriteSignedTRC(isd addr.ISD) error {
	isdCfg, err := conf.LoadISDCfg(pkicmn.GetIsdPath(pkicmn.RootDir, isd))
	if err != nil {
		return common.NewBasicError("error loading ISD config", err)
	}
	t, encoded, err := genProto(isd, isdCfg)
	if err != nil {
		return common.NewBasicError("unable to generate TRC", err)
	}
	primaryASes, err := loadPrimaryASes(isd, isdCfg, nil)
	if err != nil {
		return common.NewBasicError("error loading AS configs", err)
	}
	signed, err := signTRC(t, encoded, primaryASes)
	if err != nil {
		return common.NewBasicError("unable to partially sign TRC", err)
	}
	if err := validateAndWrite(t, signed); err != nil {
		return err
	}
	return nil
}
