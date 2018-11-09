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

	"github.com/scionproto/scion/go/lib/as_conf"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	// IssuerReissTime is the default value for Conf.IssuerReissTime. It is larger
	// than the leaf certificate validity period in order to provide optimal coverage.
	IssuerReissTime = 1*time.Hour + cert.DefaultLeafCertValidity*time.Second
	// ReissReqRate is the default interval between two consecutive reissue requests.
	ReissReqRate = 10 * time.Second
	// ReissueReqTimeout is the default timeout of a reissue request.
	ReissueReqTimeout = 5 * time.Second

	ErrorKeyConf   = "Unable to load KeyConf"
	ErrorCustomers = "Unable to load Customers"
)

type Conf struct {
	// LeafReissueLeadTime indicates how long in advance of leaf cert expiration
	// the reissuance process starts.
	LeafReissueLeadTime util.DurWrap
	// IssuerReissueLeadTime indicates how long in advance core cert expiration
	// the self reissuance process starts.
	IssuerReissueLeadTime util.DurWrap
	// ReissueRate is the interval between two consecutive reissue requests.
	ReissueRate util.DurWrap
	// ReissueTimeout is the timeout for resissue request.
	ReissueTimeout util.DurWrap
	// AutomaticRenewal whether automatic reissuing is enabled.
	AutomaticRenewal bool
}

// Init sets the uninitialized fields.
func (c *Conf) Init(confDir string) error {
	c.initDefaults()
	if c.LeafReissueLeadTime.Duration == 0 {
		if err := c.loadLeafReissTime(confDir); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conf) initDefaults() {
	if c.IssuerReissueLeadTime.Duration == 0 {
		c.IssuerReissueLeadTime.Duration = IssuerReissTime
	}
	if c.ReissueRate.Duration == 0 {
		c.ReissueRate.Duration = ReissReqRate
	}
	if c.ReissueTimeout.Duration == 0 {
		c.ReissueTimeout.Duration = ReissueReqTimeout
	}
}

// loadLeafReissTime loads the as conf and sets the LeafReissTime to the PathSegmentTTL
// to provide optimal coverage.
func (c *Conf) loadLeafReissTime(confDir string) error {
	if err := as_conf.Load(filepath.Join(confDir, as_conf.CfgName)); err != nil {
		return err
	}
	c.LeafReissueLeadTime.Duration = time.Duration(as_conf.CurrConf.PathSegmentTTL) * time.Second
	return nil
}
