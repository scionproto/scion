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

package pktcls

import (
	"net"
	"strconv"
	"strings"

	"github.com/antlr4-go/antlr/v4"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/antlr/traffic_class"
	"github.com/scionproto/scion/pkg/private/serrors"
)

type classListener struct {
	*traffic_class.BaseTrafficClassListener
	// condStack is a stack to store the Conds while the tree is parsed
	condStack []Cond
	// countStack tracks the number of children conditions for each open parent condition
	// in the parser
	countStack []int
	err        error
}

func (l *classListener) popCond() Cond {
	cond := l.condStack[len(l.condStack)-1]
	// Decrease condStack size and update indStack
	l.condStack = l.condStack[:len(l.condStack)-1]
	l.countStack = l.countStack[:len(l.countStack)-1]
	return cond
}

func (l *classListener) popConds() []Cond {
	// Copy n cond into new slice
	n := l.countStack[len(l.countStack)-1]
	conds := make([]Cond, n)
	copy(conds, l.condStack[len(l.condStack)-n:])
	// Decrease condStack size and update indStack
	l.condStack = l.condStack[:len(l.condStack)-n]
	l.countStack = l.countStack[:len(l.countStack)-1]
	return conds
}

func (l *classListener) pushCond(cond Cond) {
	l.condStack = append(l.condStack, cond)
	l.countStack[len(l.countStack)-1]++
}

// incCondDep registers a new open parent condition on the condStack
func (l *classListener) incCondDep() {
	l.countStack = append(l.countStack, 0)
}

func (l *classListener) EnterTrafficClass(ctx *traffic_class.TrafficClassContext) {
	l.incCondDep()
}

func (l *classListener) EnterMatchDst(ctx *traffic_class.MatchDstContext) {
	// Push Selector as Predicate on stack and update the number of Conds on the stack
	var err error
	mdst := &IPv4MatchDestination{}
	_, mdst.Net, err = net.ParseCIDR(ctx.GetStop().GetText())
	if err != nil {
		l.err = serrors.Wrap("CIDR parsing failed!", err, "cidr", ctx.GetStop().GetText())
	}
	l.pushCond(NewCondIPv4(mdst))
}

func (l *classListener) EnterMatchSrc(ctx *traffic_class.MatchSrcContext) {
	// Push Selector as Predicate on stack and update the number of Conds on the stack
	var err error
	msrc := &IPv4MatchSource{}
	_, msrc.Net, err = net.ParseCIDR(ctx.GetStop().GetText())
	if err != nil {
		l.err = serrors.Wrap("CIDR parsing failed!", err, "cidr", ctx.GetStop().GetText())
	}
	l.pushCond(NewCondIPv4(msrc))
}

func (l *classListener) EnterMatchDSCP(ctx *traffic_class.MatchDSCPContext) {
	// Push Selector as Predicate on stack and update the number of Conds on the stack
	mdscp := &IPv4MatchDSCP{}
	dscp, err := strconv.ParseUint(ctx.GetStop().GetText(), 16, 8)
	if err != nil {
		l.err = serrors.Wrap("DSCP parsing failed!", err, "dscp", ctx.GetStop().GetText())
	}
	mdscp.DSCP = uint8(dscp)
	l.pushCond(NewCondIPv4(mdscp))
}

func (l *classListener) EnterMatchTOS(ctx *traffic_class.MatchTOSContext) {
	// Push Selector as Predicate on stack and update the number of Conds on the stack
	mtos := &IPv4MatchToS{}
	tos, err := strconv.ParseUint(ctx.GetStop().GetText(), 16, 8)
	if err != nil {
		l.err = serrors.Wrap("TOS parsing failed!", err, "tos", ctx.GetStop().GetText())
	}
	mtos.TOS = uint8(tos)
	l.pushCond(NewCondIPv4(mtos))
}

func (l *classListener) EnterMatchProtocol(ctx *traffic_class.MatchProtocolContext) {
	// Push Selector as Predicate on stack and update the number of Conds on the stack
	prot := &IPv4MatchProtocol{}
	number, err := protocolNameToNumber(ctx.GetStop().GetText())
	if err != nil {
		l.err = serrors.Wrap("Protocol parsing failed!", err,
			"protocol", ctx.GetStop().GetText())

	}
	prot.Protocol = number
	l.pushCond(NewCondIPv4(prot))
}

func (l *classListener) EnterMatchSrcPort(ctx *traffic_class.MatchSrcPortContext) {
	// Push Selector as Predicate on stack and update the number of Conds on the stack
	src := &PortMatchSource{}
	msrc, err := strconv.ParseUint(ctx.GetStop().GetText(), 10, 16)
	if err != nil {
		l.err = serrors.Wrap("SRCPORT parsing failed!", err,
			"srcport", ctx.GetStop().GetText())

	}
	src.MinPort = uint16(msrc)
	src.MaxPort = uint16(msrc)
	l.pushCond(NewCondPorts(src))
}

func (l *classListener) EnterMatchSrcPortRange(ctx *traffic_class.MatchSrcPortRangeContext) {
	// Push Selector as Predicate on stack and update the number of Conds on the stack
	src := &PortMatchSource{}
	min := ctx.GetToken(traffic_class.TrafficClassLexerDIGITS, 0).GetText()
	max := ctx.GetToken(traffic_class.TrafficClassLexerDIGITS, 1).GetText()
	msrcMin, err := strconv.ParseUint(min, 10, 16)
	if err != nil {
		l.err = serrors.Wrap("SRCPORT parsing failed!", err, "srcport", min)
	}
	msrcMax, err := strconv.ParseUint(max, 10, 16)
	if err != nil {
		l.err = serrors.Wrap("SRCPORT parsing failed!", err, "srcport", max)
	}
	src.MinPort = uint16(msrcMin)
	src.MaxPort = uint16(msrcMax)
	l.pushCond(NewCondPorts(src))
}

func (l *classListener) EnterMatchDstPort(ctx *traffic_class.MatchDstPortContext) {
	// Push Selector as Predicate on stack and update the number of Conds on the stack
	dst := &PortMatchDestination{}
	mdst, err := strconv.ParseUint(ctx.GetStop().GetText(), 10, 16)
	if err != nil {
		l.err = serrors.Wrap("DSTPORT parsing failed!", err,
			"dstport", ctx.GetStop().GetText())

	}
	dst.MinPort = uint16(mdst)
	dst.MaxPort = uint16(mdst)
	l.pushCond(NewCondPorts(dst))
}

func (l *classListener) EnterMatchDstPortRange(ctx *traffic_class.MatchDstPortRangeContext) {
	// Push Selector as Predicate on stack and update the number of Conds on the stack
	dst := &PortMatchDestination{}
	min := ctx.GetToken(traffic_class.TrafficClassLexerDIGITS, 0).GetText()
	max := ctx.GetToken(traffic_class.TrafficClassLexerDIGITS, 1).GetText()
	mdstMin, err := strconv.ParseUint(min, 10, 16)
	if err != nil {
		l.err = serrors.Wrap("SRCPORT parsing failed!", err, "dstport", min)
	}
	mdstMax, err := strconv.ParseUint(max, 10, 16)
	if err != nil {
		l.err = serrors.Wrap("SRCPORT parsing failed!", err, "dstport", max)
	}
	dst.MinPort = uint16(mdstMin)
	dst.MaxPort = uint16(mdstMax)
	l.pushCond(NewCondPorts(dst))
}

func (l *classListener) EnterCondCls(ctx *traffic_class.CondClsContext) {
	l.pushCond(CondClass{TrafficClass: ctx.GetStop().GetText()})
}

func (l *classListener) EnterCondAny(ctx *traffic_class.CondAnyContext) {
	l.incCondDep()
}

func (l *classListener) ExitCondAny(ctx *traffic_class.CondAnyContext) {
	// Create CondAny from Conds and push it on stack
	conds := l.popConds()
	l.pushCond(NewCondAnyOf(conds...))
}

func (l *classListener) EnterCondAll(ctx *traffic_class.CondAllContext) {
	l.incCondDep()
}

func (l *classListener) ExitCondAll(ctx *traffic_class.CondAllContext) {
	// Create CondAll from Conds and push it on stack
	conds := l.popConds()
	l.pushCond(NewCondAllOf(conds...))
}

func (l *classListener) EnterCondNot(ctx *traffic_class.CondNotContext) {
	l.incCondDep()
}

func (l *classListener) ExitCondNot(ctx *traffic_class.CondNotContext) {
	// Create CondNot and push it on stack
	l.pushCond(NewCondNot(l.popCond()))
}

func (l *classListener) EnterCondBool(ctx *traffic_class.CondBoolContext) {
	bool, err := strconv.ParseBool(ctx.GetStop().GetText())
	if err != nil {
		l.err = serrors.Wrap("CondBool parsing failed!", err,
			"bool", ctx.GetStop().GetText())

	}
	l.pushCond(CondBool(bool))
}

// ValidateTrafficClass validates the structure of the class param
func ValidateTrafficClass(class string) error {
	p := buildTrafficClassParser(class)
	p.RemoveErrorListeners()
	errListener := &ErrorListener{errorType: "Parser"}
	p.AddErrorListener(errListener)
	// Walk the tree to validate the traffic class
	listener := &classListener{}
	antlr.ParseTreeWalkerDefault.Walk(listener, p.TrafficClass())
	if errListener.msg != "" {
		return serrors.New("Parsing of traffic class failed:",
			"err", errListener.msg)
	}
	if listener.err != nil {
		return listener.err
	}
	return nil
}

// BuildClassTree creates a Cond tree from the class param
func BuildClassTree(class string) (Cond, error) {
	p := buildTrafficClassParser(class)
	p.RemoveErrorListeners()
	errListener := &ErrorListener{errorType: "Parser"}
	p.AddErrorListener(errListener)
	// Walk the tree and build the traffic class
	listener := &classListener{}
	antlr.ParseTreeWalkerDefault.Walk(listener, p.TrafficClass())
	if errListener.msg != "" {
		return nil, serrors.New("Parsing of traffic class failed:",
			"err", errListener.msg)
	}
	if listener.err != nil {
		return nil, listener.err
	}
	return listener.condStack[0], nil
}

func buildTrafficClassParser(class string) *traffic_class.TrafficClassParser {
	lexer := traffic_class.NewTrafficClassLexer(
		antlr.NewInputStream(class),
	)
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(&ErrorListener{errorType: "Lexer"})
	parser := traffic_class.NewTrafficClassParser(
		antlr.NewCommonTokenStream(
			lexer,
			antlr.TokenDefaultChannel),
	)
	parser.BuildParseTrees = true
	return parser
}

// protocolNameToNumber converts protocol name (e.g. "TCP") to IP protcol
// number. The function is case insensitive.
func protocolNameToNumber(name string) (uint8, error) {
	for number, meta := range layers.IPProtocolMetadata {
		if strings.EqualFold(name, meta.Name) {
			return uint8(number), nil
		}
	}
	return 0, serrors.New("unknown IP protocol name", "name", name)
}
