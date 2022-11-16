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

// Package routing defines implementations around the routing decisions for the
// gateway.
//
// This package defines the file format for the routing policies. A routing
// policy consists of a list of rules. Each rule consists of an action and three
// matchers. Optionally, a rule can have a comment that is persisted across
// deserialization and serialization.
//
// Policies are defined in plain text. Each line represents a rule. Each rule
// consists of four whitespace separated columns. The optional comment is
// appended at the end of the line and needs to start with a '#'.
//
//	accept       1-ff00:0:110     1-ff00:0:112    10.0.1.0/24,10.0.2.0/24  # Accept from AS 110.
//	accept       2-0              1-ff00:0:112    10.0.3.0/24              # Accept from ISD 2.
//	reject       !1-ff00:0:110    1-ff00:0:112    10.0.0.0/8               # Reject unless AS 110.
//	advertise    1-ff00:0:112     1-ff00:0:110    10.0.9.0/8               # Advertise to AS 112.
//
// The first column represents the action. Currently, we support:
//
//	accept    <a> <b> <prefixes>: <b> accepts the IP prefixes <prefixes> from <a>.
//	reject    <a> <b> <prefixes>: <b> rejects the IP prefixes <prefixes> from <a>.
//	advertise <a> <b> <prefixes>: <a> advertists the IP prefixes <prefixes> to <b>.
//
// The remaining three columns define the matchers of a rule. The second and
// third column are ISD-AS matchers, the forth column is a prefix matcher.
//
// The second column matches the 'from' ISD-AS. The third column the 'to'
// ISD-AS. ISD-AS matchers support wildcards and negation:
//
//	1-ff00:0:110   Matches for 1-ff00:0:110 only.
//	0-ff00:0:110   Matches for all ASes with AS number ff00:0:110.
//	1-0            Matches for all ASes in ISD 1.
//	0-0            Matches for all ASes.
//
//	!0-ff00:0:110  Matches for all ASes except the ones with AS number 'ff00:0:110'.
//	!1-ff00:0:110  Matches for all ASes except 1-ff00:0:110.
//	!1-0           Matches for all ASes not in ISD 1.
//
// Network prefix matcher consist of a list of IP prefixes to match. The list is
// comma-separated. A prefix matches, if it is in the subset of the union of the
// IP prefixes in the list. The network prefix matcher can also be negated. The
// negation applies to the entire list. A prefix matches in the negated case, if
// it is not a subset of the union of the prefix list.
//
//	10.0.1.0/24,10.0.2.0/24    Matches all IP prefixes that are a subset of 10.0.1.0/24 or
//	                           10.0.2.0/24. It also matches 10.0.1.0/24 and 10.0.2.0/24.
//	!10.0.1.0/24,10.0.2.0/24   Matches all IP prefixes that are not a subset of 10.0.1.0/24 and
//	                           not a subset of 10.0.2.0/24.
package routing
