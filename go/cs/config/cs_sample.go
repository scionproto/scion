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

const idSample = "cs-1"

const CSSample = `
# Time between starting reissue requests and leaf cert expiration. If not
# specified, this is set to default PathSegmentTTL. (default 6h)
LeafReissueLeadTime = "6h"

# Time between self issuing core cert and core cert expiration. If not
# specified, this is set to the default leaf certificate validity time
# plus 1 hour. (default 73h)
IssuerReissueLeadTime = "73h"

# Interval between two consecutive reissue requests. (default 10s)
ReissueRate = "10s"

# Timeout for resissue request. (default 5s)
ReissueTimeout = "5s"

# Whether automatic reissuing is enabled. (default false)
AutomaticRenewal = false

# Disable the core pushing. (default false)
DisableCorePush = false
`
