// Copyright 2019 Anapaya Systems
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

package truststoragetest

import (
	"fmt"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/truststorage"
	"github.com/scionproto/scion/go/lib/util"
)

func InitTestConfig(cfg *truststorage.TrustDBConf) {
	if *cfg == nil {
		*cfg = make(truststorage.TrustDBConf)
	}
	(*cfg)[db.MaxOpenConnsKey] = "maxOpenConns"
	(*cfg)[db.MaxIdleConnsKey] = "maxIdleConns"
}

func CheckTestConfig(cfg *truststorage.TrustDBConf, id string) {
	util.LowerKeys(*cfg)
	SoMsg("MaxOpenConns", isSet(cfg.MaxOpenConns()), ShouldBeFalse)
	SoMsg("MaxIdleConns", isSet(cfg.MaxIdleConns()), ShouldBeFalse)
	SoMsg("Backend correct", cfg.Backend(), ShouldEqual, truststorage.BackendSqlite)
	SoMsg("Connection correct", cfg.Connection(), ShouldEqual,
		fmt.Sprintf("/var/lib/scion/spki/%s.trust.db", id))
}

func isSet(_ int, set bool) bool {
	return set
}
