// Copyright 2018 Anapaya Systems
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

package config

const PSSample = `
# Enable the "old" replication of down segments between cores using SegSync
# messages. (default false)
SegSync = false

# The time after which segments for a destination are refetched. (default 5m)
QueryInterval = "5m"

# The interval of crypto pushes towards the local CS. (default 30s)
CryptoSyncInterval = "30s"
`
