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

package conf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-ini/ini"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

const TrcConfFileName = "isd.ini"

// Trc holds the parameters that are used to generate a Trc.
type Trc struct {
	Isd         uint16
	Description string
	Version     uint64
	IssuingTime uint64
	Validity    uint64
	CoreIAs     []*addr.ISD_AS `ini:"-"`
	GracePeriod uint64
	QuorumTRC   uint32
}

func (t *Trc) validate() error {
	if t.Isd == 0 {
		return newValidationError("Isd")
	}
	if t.Version == 0 {
		return newValidationError("Version")
	}
	if t.Validity == 0 {
		return newValidationError("Validity")
	}
	if len(t.CoreIAs) == 0 {
		return newValidationError("CoreASes")
	} else {
		for _, ia := range t.CoreIAs {
			if ia.IAInt() == addr.IAInt(0) {
				return common.NewBasicError("Invalid core AS", nil, "ia", ia)
			}
		}
	}
	if t.QuorumTRC == 0 {
		return newValidationError("QuorumTrc")
	}
	if int(t.QuorumTRC) > len(t.CoreIAs) {
		return common.NewBasicError("QuorumTRC > # core ASes", nil)
	}
	return nil
}

func (t *Trc) SaveTo(path string, force bool) error {
	// Check if file exists and do not override without -f
	if !force {
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("%s already exists. Use -f to overwrite.\n", path)
			return nil
		}
	}
	iniCfg := ini.Empty()
	if err := ini.ReflectFrom(iniCfg, t); err != nil {
		return err
	}
	if _, err := iniCfg.Section("").NewKey("CoreASes", "0-0,0-0"); err != nil {
		return err
	}
	if err := iniCfg.SaveTo(path); err != nil {
		return err
	}
	fmt.Println("Successfully written", path)
	return nil
}

func LoadTrcConf(dir string) (*Trc, error) {
	cname := filepath.Join(dir, TrcConfFileName)
	cfg, err := ini.Load(cname)
	if err != nil {
		return nil, err
	}
	section := cfg.Section("")
	t := &Trc{}
	if err = section.MapTo(t); err != nil {
		return nil, err
	}
	// Get core ASes as comma separated list
	if !section.HasKey("CoreASes") {
		return nil, common.NewBasicError("CoreASes missing", nil)
	}
	ases := section.Key("CoreASes").Strings(",")
	// Parse into addr.ISD_AS structs
	for _, as := range ases {
		ia, err := addr.IAFromString(strings.Trim(as, " "))
		if err != nil {
			return nil, err
		}
		t.CoreIAs = append(t.CoreIAs, ia)
	}
	if t.IssuingTime == 0 {
		t.IssuingTime = uint64(time.Now().Unix())
	}
	if err = t.validate(); err != nil {
		return nil, err
	}
	return t, nil
}
