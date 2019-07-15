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

package pathstoragetest

import (
	"fmt"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/util"
)

func InitTestPathDBConf(cfg *pathstorage.PathDBConf) {
	if *cfg == nil {
		*cfg = make(pathstorage.PathDBConf)
	}
	(*cfg)[db.MaxOpenConnsKey] = "maxOpenConns"
	(*cfg)[db.MaxIdleConnsKey] = "maxIdleConns"
}

func InitTestRevCacheConf(cfg *pathstorage.RevCacheConf) {
	if *cfg == nil {
		*cfg = make(pathstorage.RevCacheConf)
	}
	(*cfg)[db.MaxOpenConnsKey] = "maxOpenConns"
	(*cfg)[db.MaxIdleConnsKey] = "maxIdleConns"
}

func CheckTestPathDBConf(cfg *pathstorage.PathDBConf, id string) {
	util.LowerKeys(*cfg)
	SoMsg("MaxOpenConns", isSet(cfg.MaxOpenConns()), ShouldBeFalse)
	SoMsg("MaxIdleConns", isSet(cfg.MaxIdleConns()), ShouldBeFalse)
	SoMsg("Backend correct", cfg.Backend(), ShouldEqual, pathstorage.BackendSqlite)
	SoMsg("Connection correct", cfg.Connection(), ShouldEqual,
		fmt.Sprintf("/var/lib/scion/pathdb/%s.path.db", id))
}

func CheckTestRevCacheConf(cfg *pathstorage.RevCacheConf) {
	util.LowerKeys(*cfg)
	SoMsg("MaxOpenConns", isSet(cfg.MaxOpenConns()), ShouldBeFalse)
	SoMsg("MaxIdleConns", isSet(cfg.MaxIdleConns()), ShouldBeFalse)
	SoMsg("Backend correct", cfg.Backend(), ShouldEqual, pathstorage.BackendMem)
}

func isSet(_ int, set bool) bool {
	return set
}
