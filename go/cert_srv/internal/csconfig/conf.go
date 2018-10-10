// Copyright 2018 ETH Zurich, Anapaya Systems
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

package csconfig

import (
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/as_conf"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	// IssuerReissTime is the default value for Conf.IssuerReissTime. It is the same
	// as the leaf certificate validity period in order to provide optimal coverage.
	IssuerReissTime = cert.DefaultLeafCertValidity * time.Second
	// ReissReqRate is the default interval between two consecutive reissue requests.
	ReissReqRate = 10 * time.Second
	// ReissueReqTimeout is the default timeout of a reissue request.
	ReissueReqTimeout = 5 * time.Second
	// SciondTimeout is the default timeout of attempting to connect to sciond.
	SciondTimeout = 20 * time.Second
	// SciondRetryInterval is the default time between sciond connect attempts.
	SciondRetryInterval = time.Second

	ErrorKeyConf   = "Unable to load KeyConf"
	ErrorCustomers = "Unable to load Customers"
)

type Conf struct {
	// LeafReissueTime is the time between starting reissue requests and leaf cert expiration.
	LeafReissueTime duration
	// IssuerReissueTime is the time between self issuing core cert and core cert expiration.
	IssuerReissueTime duration
	// ReissueRate is the interval between two consecutive reissue requests.
	ReissueRate duration
	// ReissueTimeout is the timeout for resissue request.
	ReissueTimeout duration
	// SciondPath is the sciond path. It defaults to sciond.DefaultSCIONDPath.
	SciondPath string
	// SciondTimeout is the timeout when trying to connect to sciond.
	SciondTimeout duration
	// SciondRetryInterval is the time between sciond connect attempts.
	SciondRetryInterval duration
}

// Init sets the uninitialized fields and loads the keys.
func (c *Conf) Init(confDir string) error {
	c.initDefaults()
	if c.ReissueRate.Duration <= c.ReissueTimeout.Duration {
		return common.NewBasicError("Reissue rate must not be smaller than timeout", nil,
			"rate", c.ReissueRate.Duration, "timeout", c.ReissueTimeout.Duration)
	}
	if c.LeafReissueTime.Duration == 0 {
		if err := c.loadLeafReissTime(confDir); err != nil {
			return err
		}
	}
	return nil
}

// loadLeafReissTime loads the as conf and sets the LeafReissTime to the PathSegmentTTL
// to provide optimal coverage.
func (c *Conf) loadLeafReissTime(confDir string) error {
	if err := as_conf.Load(filepath.Join(confDir, as_conf.CfgName)); err != nil {
		return err
	}
	c.LeafReissueTime.Duration = time.Duration(as_conf.CurrConf.PathSegmentTTL) * time.Second
	return nil
}

func (c *Conf) initDefaults() {
	if c.SciondPath == "" {
		c.SciondPath = sciond.DefaultSCIONDPath
	}
	if c.IssuerReissueTime.Duration == 0 {
		c.IssuerReissueTime.Duration = IssuerReissTime
	}
	if c.ReissueRate.Duration == 0 {
		c.ReissueRate.Duration = ReissReqRate
	}
	if c.ReissueTimeout.Duration == 0 {
		c.ReissueTimeout.Duration = ReissueReqTimeout
	}
	if c.SciondRetryInterval.Duration == 0 {
		c.SciondRetryInterval.Duration = SciondRetryInterval
	}
	if c.SciondTimeout.Duration == 0 {
		c.SciondTimeout.Duration = SciondTimeout
	}
}

var _ (toml.TextUnmarshaler) = (*duration)(nil)

type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = util.ParseDuration(string(text))
	return err
}
