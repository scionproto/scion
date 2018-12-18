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
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/keyconf"
)

const (
	KeyChanged   = "Verifying key has changed in the meantime"
	NotACustomer = "ISD-AS not in customer mapping"

	CustomersDir = "customers"
)

// reCustVerKey is used to parse the IA and version of a customer verifying key file.
var reCustVerKey = regexp.MustCompile(`^(ISD\S+-AS\S+)-V(\d+)\.key$`)

// Customers is a mapping from non-core ASes assigned to this core AS to their public
// verifying key.
type Customers struct {
	// trustDB is the trust database.
	trustDB trustdb.TrustDB
}

func NewCustomers(trustDB trustdb.TrustDB) *Customers {
	return &Customers{
		trustDB: trustDB,
	}
}

// loadCustomers populates the DB from assigned non-core ASes to their verifying key.
func (c *Customers) loadCustomers(stateDir string) error {
	path := filepath.Join(stateDir, CustomersDir)
	files, err := filepath.Glob(fmt.Sprintf("%s/ISD*-AS*-V*.key", path))
	if err != nil {
		return err
	}
	activeKeys := make(map[addr.IA]string)
	activeVers := make(map[addr.IA]uint64)
	for _, file := range files {
		_, name := filepath.Split(file)
		s := reCustVerKey.FindStringSubmatch(name)
		ia, err := addr.IAFromFileFmt(s[1], true)
		if err != nil {
			return common.NewBasicError("Unable to parse IA", err, "file", file)
		}
		ver, err := strconv.ParseUint(s[2], 10, 64)
		if err != nil {
			return common.NewBasicError("Unable to parse Version", err, "file", file)
		}
		if ver >= activeVers[ia] {
			activeKeys[ia] = file
			activeVers[ia] = ver
		}
	}
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	for ia, file := range activeKeys {
		key, err := keyconf.LoadKey(file, keyconf.RawKey)
		if err != nil {
			return common.NewBasicError("Unable to load key", err, "file", file)
		}
		_, dbV, err := c.trustDB.GetCustKey(ctx, ia)
		if err != nil {
			return common.NewBasicError("Failed to check DB cust key", err, "ia", ia)
		}
		if dbV >= activeVers[ia] {
			// db already contains a newer key.
			continue
		}
		err = c.trustDB.InsertCustKey(ctx, ia, activeVers[ia], key, dbV)
		if err != nil {
			return common.NewBasicError("Failed to save customer key", err, "file", file)
		}
	}
	return nil
}

// GetVerifyingKey returns the verifying key from the requested AS and nil if it is in the mapping.
// Otherwise, nil and an error.
func (c *Customers) GetVerifyingKey(ctx context.Context,
	ia addr.IA) (common.RawBytes, uint64, error) {

	k, v, err := c.trustDB.GetCustKey(ctx, ia)
	if err != nil {
		return nil, 0, err
	}
	if k == nil {
		return nil, 0, common.NewBasicError(NotACustomer, nil, "ISD-AS", ia)
	}
	return k, v, nil
}

// SetVerifyingKey sets the verifying key for a specified AS. The key is written to the file system.
func (c *Customers) SetVerifyingKey(ctx context.Context, tx trustdb.Transaction,
	ia addr.IA, newVer, oldVer uint64, newKey, oldKey common.RawBytes) error {

	return tx.InsertCustKey(ctx, ia, newVer, newKey, oldVer)
}
