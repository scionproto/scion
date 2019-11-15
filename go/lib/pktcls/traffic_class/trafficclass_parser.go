// Code generated from TrafficClass.g4 by ANTLR 4.7.1. DO NOT EDIT.

package traffic_class // TrafficClass
import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/antlr/antlr4/runtime/Go/antlr"
)

// Suppress unused import errors
var _ = fmt.Printf
var _ = reflect.Copy
var _ = strconv.Itoa

var parserATN = []uint16{
	3, 24715, 42794, 33075, 47597, 16764, 15335, 30598, 22884, 3, 22, 96, 4,
	2, 9, 2, 4, 3, 9, 3, 4, 4, 9, 4, 4, 5, 9, 5, 4, 6, 9, 6, 4, 7, 9, 7, 4,
	8, 9, 8, 4, 9, 9, 9, 4, 10, 9, 10, 4, 11, 9, 11, 4, 12, 9, 12, 4, 13, 9,
	13, 3, 2, 3, 2, 3, 2, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 3, 4, 3, 4, 3,
	4, 3, 5, 3, 5, 3, 5, 3, 5, 3, 6, 3, 6, 3, 6, 3, 7, 3, 7, 3, 7, 3, 7, 3,
	7, 7, 7, 51, 10, 7, 12, 7, 14, 7, 54, 11, 7, 3, 7, 3, 7, 3, 8, 3, 8, 3,
	8, 3, 8, 3, 8, 7, 8, 63, 10, 8, 12, 8, 14, 8, 66, 11, 8, 3, 8, 3, 8, 3,
	9, 3, 9, 3, 9, 3, 9, 3, 9, 3, 10, 3, 10, 3, 10, 3, 10, 3, 11, 3, 11, 3,
	11, 3, 11, 5, 11, 83, 10, 11, 3, 12, 3, 12, 3, 12, 3, 12, 3, 12, 3, 12,
	5, 12, 91, 10, 12, 3, 13, 3, 13, 3, 13, 3, 13, 2, 2, 14, 2, 4, 6, 8, 10,
	12, 14, 16, 18, 20, 22, 24, 2, 4, 3, 2, 12, 13, 3, 2, 9, 10, 2, 93, 2,
	26, 3, 2, 2, 2, 4, 30, 3, 2, 2, 2, 6, 34, 3, 2, 2, 2, 8, 38, 3, 2, 2, 2,
	10, 42, 3, 2, 2, 2, 12, 45, 3, 2, 2, 2, 14, 57, 3, 2, 2, 2, 16, 69, 3,
	2, 2, 2, 18, 74, 3, 2, 2, 2, 20, 82, 3, 2, 2, 2, 22, 90, 3, 2, 2, 2, 24,
	92, 3, 2, 2, 2, 26, 27, 7, 19, 2, 2, 27, 28, 7, 3, 2, 2, 28, 29, 7, 14,
	2, 2, 29, 3, 3, 2, 2, 2, 30, 31, 7, 20, 2, 2, 31, 32, 7, 3, 2, 2, 32, 33,
	7, 14, 2, 2, 33, 5, 3, 2, 2, 2, 34, 35, 7, 21, 2, 2, 35, 36, 7, 4, 2, 2,
	36, 37, 9, 2, 2, 2, 37, 7, 3, 2, 2, 2, 38, 39, 7, 22, 2, 2, 39, 40, 7,
	4, 2, 2, 40, 41, 9, 2, 2, 2, 41, 9, 3, 2, 2, 2, 42, 43, 7, 5, 2, 2, 43,
	44, 7, 12, 2, 2, 44, 11, 3, 2, 2, 2, 45, 46, 7, 15, 2, 2, 46, 47, 7, 6,
	2, 2, 47, 52, 5, 22, 12, 2, 48, 49, 7, 7, 2, 2, 49, 51, 5, 22, 12, 2, 50,
	48, 3, 2, 2, 2, 51, 54, 3, 2, 2, 2, 52, 50, 3, 2, 2, 2, 52, 53, 3, 2, 2,
	2, 53, 55, 3, 2, 2, 2, 54, 52, 3, 2, 2, 2, 55, 56, 7, 8, 2, 2, 56, 13,
	3, 2, 2, 2, 57, 58, 7, 16, 2, 2, 58, 59, 7, 6, 2, 2, 59, 64, 5, 22, 12,
	2, 60, 61, 7, 7, 2, 2, 61, 63, 5, 22, 12, 2, 62, 60, 3, 2, 2, 2, 63, 66,
	3, 2, 2, 2, 64, 62, 3, 2, 2, 2, 64, 65, 3, 2, 2, 2, 65, 67, 3, 2, 2, 2,
	66, 64, 3, 2, 2, 2, 67, 68, 7, 8, 2, 2, 68, 15, 3, 2, 2, 2, 69, 70, 7,
	17, 2, 2, 70, 71, 7, 6, 2, 2, 71, 72, 5, 22, 12, 2, 72, 73, 7, 8, 2, 2,
	73, 17, 3, 2, 2, 2, 74, 75, 7, 18, 2, 2, 75, 76, 7, 3, 2, 2, 76, 77, 9,
	3, 2, 2, 77, 19, 3, 2, 2, 2, 78, 83, 5, 2, 2, 2, 79, 83, 5, 4, 3, 2, 80,
	83, 5, 6, 4, 2, 81, 83, 5, 8, 5, 2, 82, 78, 3, 2, 2, 2, 82, 79, 3, 2, 2,
	2, 82, 80, 3, 2, 2, 2, 82, 81, 3, 2, 2, 2, 83, 21, 3, 2, 2, 2, 84, 91,
	5, 14, 8, 2, 85, 91, 5, 12, 7, 2, 86, 91, 5, 16, 9, 2, 87, 91, 5, 20, 11,
	2, 88, 91, 5, 10, 6, 2, 89, 91, 5, 18, 10, 2, 90, 84, 3, 2, 2, 2, 90, 85,
	3, 2, 2, 2, 90, 86, 3, 2, 2, 2, 90, 87, 3, 2, 2, 2, 90, 88, 3, 2, 2, 2,
	90, 89, 3, 2, 2, 2, 91, 23, 3, 2, 2, 2, 92, 93, 5, 22, 12, 2, 93, 94, 7,
	2, 2, 3, 94, 25, 3, 2, 2, 2, 6, 52, 64, 82, 90,
}
var deserializer = antlr.NewATNDeserializer(nil)
var deserializedATN = deserializer.DeserializeFromUInt16(parserATN)

var literalNames = []string{
	"", "'='", "'=0x'", "'cls='", "'('", "','", "')'", "'true'", "'false'",
}
var symbolicNames = []string{
	"", "", "", "", "", "", "", "", "", "WHITESPACE", "DIGITS", "HEX_DIGITS",
	"NET", "ANY", "ALL", "NOT", "BOOL", "SRC", "DST", "DSCP", "TOS",
}

var ruleNames = []string{
	"matchSrc", "matchDst", "matchDSCP", "matchTOS", "condCls", "condAny",
	"condAll", "condNot", "condBool", "condIPv4", "cond", "trafficClass",
}
var decisionToDFA = make([]*antlr.DFA, len(deserializedATN.DecisionToState))

func init() {
	for index, ds := range deserializedATN.DecisionToState {
		decisionToDFA[index] = antlr.NewDFA(ds, index)
	}
}

type TrafficClassParser struct {
	*antlr.BaseParser
}

func NewTrafficClassParser(input antlr.TokenStream) *TrafficClassParser {
	this := new(TrafficClassParser)

	this.BaseParser = antlr.NewBaseParser(input)

	this.Interpreter = antlr.NewParserATNSimulator(this, deserializedATN, decisionToDFA,
		antlr.NewPredictionContextCache())
	this.RuleNames = ruleNames
	this.LiteralNames = literalNames
	this.SymbolicNames = symbolicNames
	this.GrammarFileName = "TrafficClass.g4"

	return this
}

// TrafficClassParser tokens.
const (
	TrafficClassParserEOF        = antlr.TokenEOF
	TrafficClassParserT__0       = 1
	TrafficClassParserT__1       = 2
	TrafficClassParserT__2       = 3
	TrafficClassParserT__3       = 4
	TrafficClassParserT__4       = 5
	TrafficClassParserT__5       = 6
	TrafficClassParserT__6       = 7
	TrafficClassParserT__7       = 8
	TrafficClassParserWHITESPACE = 9
	TrafficClassParserDIGITS     = 10
	TrafficClassParserHEX_DIGITS = 11
	TrafficClassParserNET        = 12
	TrafficClassParserANY        = 13
	TrafficClassParserALL        = 14
	TrafficClassParserNOT        = 15
	TrafficClassParserBOOL       = 16
	TrafficClassParserSRC        = 17
	TrafficClassParserDST        = 18
	TrafficClassParserDSCP       = 19
	TrafficClassParserTOS        = 20
)

// TrafficClassParser rules.
const (
	TrafficClassParserRULE_matchSrc     = 0
	TrafficClassParserRULE_matchDst     = 1
	TrafficClassParserRULE_matchDSCP    = 2
	TrafficClassParserRULE_matchTOS     = 3
	TrafficClassParserRULE_condCls      = 4
	TrafficClassParserRULE_condAny      = 5
	TrafficClassParserRULE_condAll      = 6
	TrafficClassParserRULE_condNot      = 7
	TrafficClassParserRULE_condBool     = 8
	TrafficClassParserRULE_condIPv4     = 9
	TrafficClassParserRULE_cond         = 10
	TrafficClassParserRULE_trafficClass = 11
)

// IMatchSrcContext is an interface to support dynamic dispatch.
type IMatchSrcContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsMatchSrcContext differentiates from other interfaces.
	IsMatchSrcContext()
}

type MatchSrcContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyMatchSrcContext() *MatchSrcContext {
	var p = new(MatchSrcContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_matchSrc
	return p
}

func (*MatchSrcContext) IsMatchSrcContext() {}

func NewMatchSrcContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *MatchSrcContext {

	var p = new(MatchSrcContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_matchSrc

	return p
}

func (s *MatchSrcContext) GetParser() antlr.Parser { return s.parser }

func (s *MatchSrcContext) SRC() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserSRC, 0)
}

func (s *MatchSrcContext) NET() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserNET, 0)
}

func (s *MatchSrcContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *MatchSrcContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *MatchSrcContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterMatchSrc(s)
	}
}

func (s *MatchSrcContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitMatchSrc(s)
	}
}

func (p *TrafficClassParser) MatchSrc() (localctx IMatchSrcContext) {
	localctx = NewMatchSrcContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 0, TrafficClassParserRULE_matchSrc)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(24)
		p.Match(TrafficClassParserSRC)
	}
	{
		p.SetState(25)
		p.Match(TrafficClassParserT__0)
	}
	{
		p.SetState(26)
		p.Match(TrafficClassParserNET)
	}

	return localctx
}

// IMatchDstContext is an interface to support dynamic dispatch.
type IMatchDstContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsMatchDstContext differentiates from other interfaces.
	IsMatchDstContext()
}

type MatchDstContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyMatchDstContext() *MatchDstContext {
	var p = new(MatchDstContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_matchDst
	return p
}

func (*MatchDstContext) IsMatchDstContext() {}

func NewMatchDstContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *MatchDstContext {

	var p = new(MatchDstContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_matchDst

	return p
}

func (s *MatchDstContext) GetParser() antlr.Parser { return s.parser }

func (s *MatchDstContext) DST() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserDST, 0)
}

func (s *MatchDstContext) NET() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserNET, 0)
}

func (s *MatchDstContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *MatchDstContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *MatchDstContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterMatchDst(s)
	}
}

func (s *MatchDstContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitMatchDst(s)
	}
}

func (p *TrafficClassParser) MatchDst() (localctx IMatchDstContext) {
	localctx = NewMatchDstContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 2, TrafficClassParserRULE_matchDst)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(28)
		p.Match(TrafficClassParserDST)
	}
	{
		p.SetState(29)
		p.Match(TrafficClassParserT__0)
	}
	{
		p.SetState(30)
		p.Match(TrafficClassParserNET)
	}

	return localctx
}

// IMatchDSCPContext is an interface to support dynamic dispatch.
type IMatchDSCPContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsMatchDSCPContext differentiates from other interfaces.
	IsMatchDSCPContext()
}

type MatchDSCPContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyMatchDSCPContext() *MatchDSCPContext {
	var p = new(MatchDSCPContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_matchDSCP
	return p
}

func (*MatchDSCPContext) IsMatchDSCPContext() {}

func NewMatchDSCPContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *MatchDSCPContext {

	var p = new(MatchDSCPContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_matchDSCP

	return p
}

func (s *MatchDSCPContext) GetParser() antlr.Parser { return s.parser }

func (s *MatchDSCPContext) DSCP() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserDSCP, 0)
}

func (s *MatchDSCPContext) HEX_DIGITS() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserHEX_DIGITS, 0)
}

func (s *MatchDSCPContext) DIGITS() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserDIGITS, 0)
}

func (s *MatchDSCPContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *MatchDSCPContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *MatchDSCPContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterMatchDSCP(s)
	}
}

func (s *MatchDSCPContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitMatchDSCP(s)
	}
}

func (p *TrafficClassParser) MatchDSCP() (localctx IMatchDSCPContext) {
	localctx = NewMatchDSCPContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 4, TrafficClassParserRULE_matchDSCP)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(32)
		p.Match(TrafficClassParserDSCP)
	}
	{
		p.SetState(33)
		p.Match(TrafficClassParserT__1)
	}
	{
		p.SetState(34)
		_la = p.GetTokenStream().LA(1)

		if !(_la == TrafficClassParserDIGITS || _la == TrafficClassParserHEX_DIGITS) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

	return localctx
}

// IMatchTOSContext is an interface to support dynamic dispatch.
type IMatchTOSContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsMatchTOSContext differentiates from other interfaces.
	IsMatchTOSContext()
}

type MatchTOSContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyMatchTOSContext() *MatchTOSContext {
	var p = new(MatchTOSContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_matchTOS
	return p
}

func (*MatchTOSContext) IsMatchTOSContext() {}

func NewMatchTOSContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *MatchTOSContext {

	var p = new(MatchTOSContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_matchTOS

	return p
}

func (s *MatchTOSContext) GetParser() antlr.Parser { return s.parser }

func (s *MatchTOSContext) TOS() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserTOS, 0)
}

func (s *MatchTOSContext) HEX_DIGITS() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserHEX_DIGITS, 0)
}

func (s *MatchTOSContext) DIGITS() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserDIGITS, 0)
}

func (s *MatchTOSContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *MatchTOSContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *MatchTOSContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterMatchTOS(s)
	}
}

func (s *MatchTOSContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitMatchTOS(s)
	}
}

func (p *TrafficClassParser) MatchTOS() (localctx IMatchTOSContext) {
	localctx = NewMatchTOSContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 6, TrafficClassParserRULE_matchTOS)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(36)
		p.Match(TrafficClassParserTOS)
	}
	{
		p.SetState(37)
		p.Match(TrafficClassParserT__1)
	}
	{
		p.SetState(38)
		_la = p.GetTokenStream().LA(1)

		if !(_la == TrafficClassParserDIGITS || _la == TrafficClassParserHEX_DIGITS) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

	return localctx
}

// ICondClsContext is an interface to support dynamic dispatch.
type ICondClsContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsCondClsContext differentiates from other interfaces.
	IsCondClsContext()
}

type CondClsContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyCondClsContext() *CondClsContext {
	var p = new(CondClsContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_condCls
	return p
}

func (*CondClsContext) IsCondClsContext() {}

func NewCondClsContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *CondClsContext {

	var p = new(CondClsContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_condCls

	return p
}

func (s *CondClsContext) GetParser() antlr.Parser { return s.parser }

func (s *CondClsContext) DIGITS() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserDIGITS, 0)
}

func (s *CondClsContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CondClsContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CondClsContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterCondCls(s)
	}
}

func (s *CondClsContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitCondCls(s)
	}
}

func (p *TrafficClassParser) CondCls() (localctx ICondClsContext) {
	localctx = NewCondClsContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 8, TrafficClassParserRULE_condCls)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(40)
		p.Match(TrafficClassParserT__2)
	}
	{
		p.SetState(41)
		p.Match(TrafficClassParserDIGITS)
	}

	return localctx
}

// ICondAnyContext is an interface to support dynamic dispatch.
type ICondAnyContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsCondAnyContext differentiates from other interfaces.
	IsCondAnyContext()
}

type CondAnyContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyCondAnyContext() *CondAnyContext {
	var p = new(CondAnyContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_condAny
	return p
}

func (*CondAnyContext) IsCondAnyContext() {}

func NewCondAnyContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *CondAnyContext {

	var p = new(CondAnyContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_condAny

	return p
}

func (s *CondAnyContext) GetParser() antlr.Parser { return s.parser }

func (s *CondAnyContext) ANY() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserANY, 0)
}

func (s *CondAnyContext) AllCond() []ICondContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*ICondContext)(nil)).Elem())
	var tst = make([]ICondContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(ICondContext)
		}
	}

	return tst
}

func (s *CondAnyContext) Cond(i int) ICondContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICondContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(ICondContext)
}

func (s *CondAnyContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CondAnyContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CondAnyContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterCondAny(s)
	}
}

func (s *CondAnyContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitCondAny(s)
	}
}

func (p *TrafficClassParser) CondAny() (localctx ICondAnyContext) {
	localctx = NewCondAnyContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 10, TrafficClassParserRULE_condAny)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(43)
		p.Match(TrafficClassParserANY)
	}
	{
		p.SetState(44)
		p.Match(TrafficClassParserT__3)
	}
	{
		p.SetState(45)
		p.Cond()
	}
	p.SetState(50)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == TrafficClassParserT__4 {
		{
			p.SetState(46)
			p.Match(TrafficClassParserT__4)
		}
		{
			p.SetState(47)
			p.Cond()
		}

		p.SetState(52)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(53)
		p.Match(TrafficClassParserT__5)
	}

	return localctx
}

// ICondAllContext is an interface to support dynamic dispatch.
type ICondAllContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsCondAllContext differentiates from other interfaces.
	IsCondAllContext()
}

type CondAllContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyCondAllContext() *CondAllContext {
	var p = new(CondAllContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_condAll
	return p
}

func (*CondAllContext) IsCondAllContext() {}

func NewCondAllContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *CondAllContext {

	var p = new(CondAllContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_condAll

	return p
}

func (s *CondAllContext) GetParser() antlr.Parser { return s.parser }

func (s *CondAllContext) ALL() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserALL, 0)
}

func (s *CondAllContext) AllCond() []ICondContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*ICondContext)(nil)).Elem())
	var tst = make([]ICondContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(ICondContext)
		}
	}

	return tst
}

func (s *CondAllContext) Cond(i int) ICondContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICondContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(ICondContext)
}

func (s *CondAllContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CondAllContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CondAllContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterCondAll(s)
	}
}

func (s *CondAllContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitCondAll(s)
	}
}

func (p *TrafficClassParser) CondAll() (localctx ICondAllContext) {
	localctx = NewCondAllContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 12, TrafficClassParserRULE_condAll)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(55)
		p.Match(TrafficClassParserALL)
	}
	{
		p.SetState(56)
		p.Match(TrafficClassParserT__3)
	}
	{
		p.SetState(57)
		p.Cond()
	}
	p.SetState(62)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == TrafficClassParserT__4 {
		{
			p.SetState(58)
			p.Match(TrafficClassParserT__4)
		}
		{
			p.SetState(59)
			p.Cond()
		}

		p.SetState(64)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(65)
		p.Match(TrafficClassParserT__5)
	}

	return localctx
}

// ICondNotContext is an interface to support dynamic dispatch.
type ICondNotContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsCondNotContext differentiates from other interfaces.
	IsCondNotContext()
}

type CondNotContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyCondNotContext() *CondNotContext {
	var p = new(CondNotContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_condNot
	return p
}

func (*CondNotContext) IsCondNotContext() {}

func NewCondNotContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *CondNotContext {

	var p = new(CondNotContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_condNot

	return p
}

func (s *CondNotContext) GetParser() antlr.Parser { return s.parser }

func (s *CondNotContext) NOT() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserNOT, 0)
}

func (s *CondNotContext) Cond() ICondContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICondContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICondContext)
}

func (s *CondNotContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CondNotContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CondNotContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterCondNot(s)
	}
}

func (s *CondNotContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitCondNot(s)
	}
}

func (p *TrafficClassParser) CondNot() (localctx ICondNotContext) {
	localctx = NewCondNotContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 14, TrafficClassParserRULE_condNot)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(67)
		p.Match(TrafficClassParserNOT)
	}
	{
		p.SetState(68)
		p.Match(TrafficClassParserT__3)
	}
	{
		p.SetState(69)
		p.Cond()
	}
	{
		p.SetState(70)
		p.Match(TrafficClassParserT__5)
	}

	return localctx
}

// ICondBoolContext is an interface to support dynamic dispatch.
type ICondBoolContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsCondBoolContext differentiates from other interfaces.
	IsCondBoolContext()
}

type CondBoolContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyCondBoolContext() *CondBoolContext {
	var p = new(CondBoolContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_condBool
	return p
}

func (*CondBoolContext) IsCondBoolContext() {}

func NewCondBoolContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *CondBoolContext {

	var p = new(CondBoolContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_condBool

	return p
}

func (s *CondBoolContext) GetParser() antlr.Parser { return s.parser }

func (s *CondBoolContext) BOOL() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserBOOL, 0)
}

func (s *CondBoolContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CondBoolContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CondBoolContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterCondBool(s)
	}
}

func (s *CondBoolContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitCondBool(s)
	}
}

func (p *TrafficClassParser) CondBool() (localctx ICondBoolContext) {
	localctx = NewCondBoolContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 16, TrafficClassParserRULE_condBool)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(72)
		p.Match(TrafficClassParserBOOL)
	}
	{
		p.SetState(73)
		p.Match(TrafficClassParserT__0)
	}
	{
		p.SetState(74)
		_la = p.GetTokenStream().LA(1)

		if !(_la == TrafficClassParserT__6 || _la == TrafficClassParserT__7) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

	return localctx
}

// ICondIPv4Context is an interface to support dynamic dispatch.
type ICondIPv4Context interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsCondIPv4Context differentiates from other interfaces.
	IsCondIPv4Context()
}

type CondIPv4Context struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyCondIPv4Context() *CondIPv4Context {
	var p = new(CondIPv4Context)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_condIPv4
	return p
}

func (*CondIPv4Context) IsCondIPv4Context() {}

func NewCondIPv4Context(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *CondIPv4Context {

	var p = new(CondIPv4Context)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_condIPv4

	return p
}

func (s *CondIPv4Context) GetParser() antlr.Parser { return s.parser }

func (s *CondIPv4Context) MatchSrc() IMatchSrcContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IMatchSrcContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IMatchSrcContext)
}

func (s *CondIPv4Context) MatchDst() IMatchDstContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IMatchDstContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IMatchDstContext)
}

func (s *CondIPv4Context) MatchDSCP() IMatchDSCPContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IMatchDSCPContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IMatchDSCPContext)
}

func (s *CondIPv4Context) MatchTOS() IMatchTOSContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IMatchTOSContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IMatchTOSContext)
}

func (s *CondIPv4Context) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CondIPv4Context) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CondIPv4Context) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterCondIPv4(s)
	}
}

func (s *CondIPv4Context) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitCondIPv4(s)
	}
}

func (p *TrafficClassParser) CondIPv4() (localctx ICondIPv4Context) {
	localctx = NewCondIPv4Context(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 18, TrafficClassParserRULE_condIPv4)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(80)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case TrafficClassParserSRC:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(76)
			p.MatchSrc()
		}

	case TrafficClassParserDST:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(77)
			p.MatchDst()
		}

	case TrafficClassParserDSCP:
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(78)
			p.MatchDSCP()
		}

	case TrafficClassParserTOS:
		p.EnterOuterAlt(localctx, 4)
		{
			p.SetState(79)
			p.MatchTOS()
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// ICondContext is an interface to support dynamic dispatch.
type ICondContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsCondContext differentiates from other interfaces.
	IsCondContext()
}

type CondContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyCondContext() *CondContext {
	var p = new(CondContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_cond
	return p
}

func (*CondContext) IsCondContext() {}

func NewCondContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *CondContext {

	var p = new(CondContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_cond

	return p
}

func (s *CondContext) GetParser() antlr.Parser { return s.parser }

func (s *CondContext) CondAll() ICondAllContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICondAllContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICondAllContext)
}

func (s *CondContext) CondAny() ICondAnyContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICondAnyContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICondAnyContext)
}

func (s *CondContext) CondNot() ICondNotContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICondNotContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICondNotContext)
}

func (s *CondContext) CondIPv4() ICondIPv4Context {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICondIPv4Context)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICondIPv4Context)
}

func (s *CondContext) CondCls() ICondClsContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICondClsContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICondClsContext)
}

func (s *CondContext) CondBool() ICondBoolContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICondBoolContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICondBoolContext)
}

func (s *CondContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CondContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CondContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterCond(s)
	}
}

func (s *CondContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitCond(s)
	}
}

func (p *TrafficClassParser) Cond() (localctx ICondContext) {
	localctx = NewCondContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 20, TrafficClassParserRULE_cond)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(88)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case TrafficClassParserALL:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(82)
			p.CondAll()
		}

	case TrafficClassParserANY:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(83)
			p.CondAny()
		}

	case TrafficClassParserNOT:
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(84)
			p.CondNot()
		}

	case TrafficClassParserSRC, TrafficClassParserDST, TrafficClassParserDSCP,
		TrafficClassParserTOS:

		p.EnterOuterAlt(localctx, 4)
		{
			p.SetState(85)
			p.CondIPv4()
		}

	case TrafficClassParserT__2:
		p.EnterOuterAlt(localctx, 5)
		{
			p.SetState(86)
			p.CondCls()
		}

	case TrafficClassParserBOOL:
		p.EnterOuterAlt(localctx, 6)
		{
			p.SetState(87)
			p.CondBool()
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// ITrafficClassContext is an interface to support dynamic dispatch.
type ITrafficClassContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsTrafficClassContext differentiates from other interfaces.
	IsTrafficClassContext()
}

type TrafficClassContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyTrafficClassContext() *TrafficClassContext {
	var p = new(TrafficClassContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = TrafficClassParserRULE_trafficClass
	return p
}

func (*TrafficClassContext) IsTrafficClassContext() {}

func NewTrafficClassContext(parser antlr.Parser, parent antlr.ParserRuleContext,
	invokingState int) *TrafficClassContext {

	var p = new(TrafficClassContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = TrafficClassParserRULE_trafficClass

	return p
}

func (s *TrafficClassContext) GetParser() antlr.Parser { return s.parser }

func (s *TrafficClassContext) Cond() ICondContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICondContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICondContext)
}

func (s *TrafficClassContext) EOF() antlr.TerminalNode {
	return s.GetToken(TrafficClassParserEOF, 0)
}

func (s *TrafficClassContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *TrafficClassContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *TrafficClassContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.EnterTrafficClass(s)
	}
}

func (s *TrafficClassContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(TrafficClassListener); ok {
		listenerT.ExitTrafficClass(s)
	}
}

func (p *TrafficClassParser) TrafficClass() (localctx ITrafficClassContext) {
	localctx = NewTrafficClassContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 22, TrafficClassParserRULE_trafficClass)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(90)
		p.Cond()
	}
	{
		p.SetState(91)
		p.Match(TrafficClassParserEOF)
	}

	return localctx
}
