// Copyright 2020 Anapaya Systems
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

package storage

const sample = `
# Connection for the database.
connection = "%s"

# The maximum number of open connections to the database. In case of 0,
# the limit is not set and uses the go default. (default 0)
max_open_conns = 0

# The maximum number of idle connections to the database. In case of 0,
# the limit is not set and uses the go default. (default 0)
max_idle_conns = 0
`
