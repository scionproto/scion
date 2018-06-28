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
	"os"
	"path/filepath"
	"time"

	"github.com/go-ini/ini"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

const IsdConfFileName = "isd.ini"

const (
	ErrCoreIANotSet               = "Core ASes are not specified"
	ErrInvalidCoreIA              = "Invalid Core ASes"
	ErrInvalidGracePeriod         = "Invalid Grace Period Duration"
	ErrQuorumTrcGreaterThanCoreIA = "QuorumTRC > # Core ASes"
	ErrQuorumTrcNotSet            = "Quorum TRC not set"
	ErrTrcVersionNotSet           = "Version not set for TRC"
)

// Isd holds config parameters read from isd.ini.
type Isd struct {
	Desc string `comment:"General description for the ISD"`
	*Trc `ini:"TRC"`
}

func LoadIsdConf(dir string) (*Isd, error) {
	cname := filepath.Join(dir, IsdConfFileName)
	cfg, err := ini.Load(cname)
	if err != nil {
		return nil, err
	}
	i := &Isd{}
	if err = cfg.MapTo(i); err != nil {
		return nil, err
	}
	if len(i.Trc.RawCoreIAs) == 0 {
		return nil, common.NewBasicError("CoreASes missing", nil)
	}
	// Parse core ASes into addr.IAs
	for _, raw := range i.Trc.RawCoreIAs {
		ia, err := addr.IAFromString(raw)
		if err != nil {
			return nil, err
		}
		i.Trc.CoreIAs = append(i.Trc.CoreIAs, ia)
	}
	if err = i.Trc.validate(); err != nil {
		return nil, err
	}
	return i, nil
}

func (i *Isd) Write(path string, force bool) error {
	// Check if file exists and do not override without -f
	if !force {
		if _, err := os.Stat(path); err == nil {
			pkicmn.QuietPrint("%s already exists. Use -f to overwrite.\n", path)
			return nil
		}
	}
	// Make sure RawCoreIAs and CoreIAs are in sync.
	i.Trc.RawCoreIAs = make([]string, len(i.Trc.CoreIAs))
	for idx, ia := range i.Trc.CoreIAs {
		i.Trc.RawCoreIAs[idx] = ia.String()
	}
	// Make sure RawValidity and Validity are in sync.
	i.Trc.RawValidity = util.FmtDuration(i.Trc.Validity)
	i.Trc.RawGracePeriod = util.FmtDuration(i.Trc.GracePeriod)
	iniCfg := ini.Empty()
	if err := ini.ReflectFrom(iniCfg, i); err != nil {
		return err
	}
	if err := iniCfg.SaveTo(path); err != nil {
		return err
	}
	pkicmn.QuietPrint("Successfully written %s\n", path)
	return nil
}

// Trc holds the parameters that are used to generate a Trc.
type Trc struct {
	Version        uint64        `comment:"The version of the TRC. Must not be 0."`
	IssuingTime    uint32        `comment:"Time of issuance as UNIX epoch. If 0 will be set to now."`
	Validity       time.Duration `ini:"-"`
	RawValidity    string        `ini:"Validity" comment:"The validity of the certificate as duration string, e.g., 180d or 36h"`
	CoreIAs        []addr.IA     `ini:"-"`
	RawCoreIAs     []string      `ini:"CoreASes" comment:"The core ASes of this ISD as comma-separated list, e.g., 1-ff00:0:0,1-ff00:0:1"`
	GracePeriod    time.Duration `ini:"-"`
	RawGracePeriod string        `ini:"GracePeriod" comment:"The grace period for the previous TRC as duration string (see above)"`
	QuorumTRC      uint32        `comment:"The number of core ASes needed to update the TRC"`
}

func (t *Trc) validate() error {
	if t.IssuingTime == 0 {
		t.IssuingTime = uint32(time.Now().Unix())
	}
	if t.Version == 0 {
		return common.NewBasicError(ErrTrcVersionNotSet, nil)
	}
	if t.RawValidity == "" {
		t.RawValidity = "0s"
	}
	var err error
	t.Validity, err = util.ParseDuration(t.RawValidity)
	if err != nil {
		return common.NewBasicError(ErrInvalidValidityDuration, nil, "duration", t.RawValidity)
	}
	if int64(t.Validity) == 0 {
		return common.NewBasicError(ErrValidityDurationNotSet, nil)
	}
	if len(t.CoreIAs) == 0 {
		return common.NewBasicError(ErrCoreIANotSet, nil)
	} else {
		for _, ia := range t.CoreIAs {
			if ia.I == 0 || ia.A == 0 {
				return common.NewBasicError(ErrInvalidCoreIA, nil, "ia", ia)
			}
		}
	}
	if t.RawGracePeriod == "" {
		t.RawGracePeriod = "0s"
	}
	t.GracePeriod, err = util.ParseDuration(t.RawGracePeriod)
	if err != nil {
		return common.NewBasicError(ErrInvalidGracePeriod, nil, "duration", t.RawGracePeriod)
	}
	if t.QuorumTRC == 0 {
		return common.NewBasicError(ErrQuorumTrcNotSet, nil)
	}
	if int(t.QuorumTRC) > len(t.CoreIAs) {
		return common.NewBasicError(ErrQuorumTrcGreaterThanCoreIA, nil)
	}
	return nil
}
