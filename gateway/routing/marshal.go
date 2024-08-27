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

package routing

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"text/tabwriter"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// MarshalText marshals the policy.
func (p Policy) MarshalText() ([]byte, error) {
	var buf bytes.Buffer
	writer := tabwriter.NewWriter(&buf, 0, 0, 4, ' ', 0)

	for _, rule := range p.Rules {
		var nextHop string
		if rule.NextHop != nil {
			nextHop = rule.NextHop.String()
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t", rule.Action, rule.From, rule.To, rule.Network,
			nextHop)
		if len(rule.Comment) != 0 {
			fmt.Fprintf(writer, "# %s", rule.Comment)
		}
		fmt.Fprintln(writer)
	}
	if err := writer.Flush(); err != nil {
		return nil, err
	}
	return stripSpaces(buf.Bytes())
}

// UnmarshalText unmarshals a policy.
func (p *Policy) UnmarshalText(b []byte) error {
	var rules []Rule

	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		rule, err := parseRule(scanner.Bytes())
		if err != nil {
			return serrors.Wrap("parsing rule", err, "line", len(rules))
		}
		rules = append(rules, rule)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	p.Rules = rules
	return nil
}

func parseRule(b []byte) (Rule, error) {
	commentIndex := bytes.Index(b, []byte("#"))
	var comment string
	if commentIndex >= 0 {
		comment = strings.TrimRight(strings.TrimPrefix(string(b[commentIndex+1:]), " "), " ")
		b = b[:commentIndex]
	}
	columns := bytes.Fields(b)
	if len(columns) < 4 {
		return Rule{}, serrors.New("invalid number of columns", "columns", len(columns))
	}

	action, err := parseAction(columns[0])
	if err != nil {
		return Rule{}, serrors.Wrap("parsing 'action'", err, "input", string(columns[0]))
	}
	fromMatcher, err := parseIAMatcher(columns[1])
	if err != nil {
		return Rule{}, serrors.Wrap("parsing 'to'", err, "input", string(columns[1]))
	}
	toMatcher, err := parseIAMatcher(columns[2])
	if err != nil {
		return Rule{}, serrors.Wrap("parsing 'from'", err, "input", string(columns[2]))
	}
	networkMatcher, err := parseNetworkMatcher(columns[3])
	if err != nil {
		return Rule{}, serrors.Wrap("parsing 'network'", err, "input", string(columns[3]))
	}

	maxColumns := 4
	if action == Advertise {
		maxColumns = 5
	}
	if len(columns) > maxColumns {
		return Rule{}, serrors.New("invalid number of columns", "columns", len(columns))
	}

	var nextHop net.IP
	if len(columns) >= 5 {
		nextHop = net.ParseIP(string(columns[4]))
		if nextHop == nil {
			return Rule{}, serrors.New("invalid pingable address", "input", string(columns[4]))
		}
	}

	return Rule{
		Action:  action,
		To:      toMatcher,
		From:    fromMatcher,
		Network: networkMatcher,
		NextHop: nextHop,
		Comment: comment,
	}, nil
}

func parseIAMatcher(b []byte) (IAMatcher, error) {
	var negative bool
	if bytes.HasPrefix(b, []byte("!")) {
		negative = true
		b = b[1:]
	}
	ia, err := addr.ParseIA(string(b))
	if err != nil {
		return nil, err
	}
	if !negative {
		return SingleIAMatcher{IA: ia}, nil
	}
	return NegatedIAMatcher{IAMatcher: SingleIAMatcher{IA: ia}}, nil
}

func parseNetworkMatcher(b []byte) (NetworkMatcher, error) {
	var negative bool
	if bytes.HasPrefix(b, []byte("!")) {
		negative = true
		b = b[1:]
	}
	var networks []netip.Prefix
	for _, network := range bytes.Split(b, []byte(",")) {
		n, err := netip.ParsePrefix(string(network))
		if err != nil {
			return NetworkMatcher{}, serrors.Wrap("parsing network", err)
		}
		networks = append(networks, n)
	}
	return NetworkMatcher{
		Allowed: networks,
		Negated: negative,
	}, nil
}

func parseAction(b []byte) (Action, error) {
	switch string(b) {
	case Accept.String():
		return Accept, nil
	case Reject.String():
		return Reject, nil
	case Advertise.String():
		return Advertise, nil
	case RedistributeBGP.String():
		return RedistributeBGP, nil
	default:
		return 0, serrors.New("unknown action", "input", string(b))
	}
}

func stripSpaces(input []byte) ([]byte, error) {
	var output bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(input))
	for scanner.Scan() {
		if _, err := output.Write(bytes.TrimRight(scanner.Bytes(), " ")); err != nil {
			return nil, err
		}
		if _, err := output.WriteString("\n"); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
