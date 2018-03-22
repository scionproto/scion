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
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/trust"
)

const (
	KeyChanged   = "Verifying key has changed in the meantime"
	NotACustomer = "ISD-AS not in custommer mapping"
	CustomersDir = "customers"
)

type Customers map[addr.IA]common.RawBytes

// LoadCustomers populates the mapping from assigned non-core ASes to their respective verifying key.
func (c *Conf) LoadCustomers() (Customers, error) {
	path := filepath.Join(c.StateDir, CustomersDir)
	files, err := filepath.Glob(fmt.Sprintf("%s/ISD*-AS*-V*.key", path))
	if err != nil {
		return nil, err
	}
	activeKeys := make(map[addr.IA]string)
	activeVers := make(map[addr.IA]uint64)
	for _, file := range files {
		re := regexp.MustCompile(`ISD(\d+)-AS([\d_]+)-V(\d+)\.key$`)
		s := re.FindStringSubmatch(file)
		ia, err := addr.IAFromString(fmt.Sprintf("%s-%s", s[1], s[2]))
		if err != nil {
			return nil, common.NewBasicError("Unable to parse IA", err, "file", file)
		}
		ver, err := strconv.ParseUint(s[3], 10, 64)
		if err != nil {
			return nil, common.NewBasicError("Unable to parse Version", err, "file", file)
		}
		if uint64(ver) >= activeVers[ia] {
			activeKeys[ia] = file
			activeVers[ia] = uint64(ver)
		}
	}
	customers := make(map[addr.IA]common.RawBytes)
	for ia, file := range activeKeys {
		key, err := trust.LoadKey(file)
		if err != nil {
			return nil, common.NewBasicError("Unable to load key", err, "file", file)
		}
		customers[ia] = key
	}
	return customers, nil
}

// GetVerifyingKey returns the verifying key from the requested AS and nil if it is in the mapping.
// Otherwise, nil and an error.
func (c *Conf) GetVerifyingKey(ia addr.IA) (common.RawBytes, error) {
	c.customersLock.RLock()
	defer c.customersLock.RUnlock()
	b, ok := c.customers[ia]
	if !ok {
		return nil, common.NewBasicError(NotACustomer, nil)
	}
	return b, nil
}

// SetVerifyingKey sets the verifying key for a specified AS. The key is written to the file system.
func (c *Conf) SetVerifyingKey(ia addr.IA, ver uint64, newKey, oldKey common.RawBytes) error {
	c.customersLock.Lock()
	defer c.customersLock.Unlock()
	currKey, ok := c.customers[ia]
	if !ok {
		return common.NewBasicError(NotACustomer, nil, "ISD-AS", ia)
	}
	// Check that the key in the mapping has not changed in the mean time
	if !bytes.Equal(currKey, oldKey) {
		return common.NewBasicError(KeyChanged, nil, "ISD-AS", ia)
	}
	// Key has to be written to file system, only if it has changed
	if !bytes.Equal(newKey, currKey) {
		var err error
		name := fmt.Sprintf("ISD%d-AS%s-V%d.key", ia.I, ia.A, ver)
		path := filepath.Join(c.StateDir, CustomersDir, name)
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			return err
		}
		buf := make([]byte, base64.StdEncoding.EncodedLen(len(newKey)))
		base64.StdEncoding.Encode(buf, newKey)
		if err = ioutil.WriteFile(path, buf, 0644); err != nil {
			return err
		}
		c.customers[ia] = make(common.RawBytes, len(newKey))
		copy(c.customers[ia], newKey)
		return nil
	}
	return nil
}
