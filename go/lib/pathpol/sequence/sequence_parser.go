// Code generated from Sequence.g4 by ANTLR 4.7.1. DO NOT EDIT.

package sequence // Sequence
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
	3, 24715, 42794, 33075, 47597, 16764, 15335, 30598, 22884, 3, 16, 73, 4,
	2, 9, 2, 4, 3, 9, 3, 4, 4, 9, 4, 4, 5, 9, 5, 4, 6, 9, 6, 4, 7, 9, 7, 3,
	2, 3, 2, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 5, 3, 24, 10, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 7, 3, 37,
	10, 3, 12, 3, 14, 3, 40, 11, 3, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3,
	4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 5, 4, 58, 10,
	4, 3, 5, 3, 5, 5, 5, 62, 10, 5, 3, 6, 3, 6, 3, 6, 5, 6, 67, 10, 6, 3, 7,
	3, 7, 5, 7, 71, 10, 7, 3, 7, 2, 3, 4, 8, 2, 4, 6, 8, 10, 12, 2, 2, 2, 79,
	2, 14, 3, 2, 2, 2, 4, 23, 3, 2, 2, 2, 6, 57, 3, 2, 2, 2, 8, 61, 3, 2, 2,
	2, 10, 66, 3, 2, 2, 2, 12, 70, 3, 2, 2, 2, 14, 15, 5, 4, 3, 2, 15, 16,
	7, 2, 2, 3, 16, 3, 3, 2, 2, 2, 17, 18, 8, 3, 1, 2, 18, 19, 7, 15, 2, 2,
	19, 20, 5, 4, 3, 2, 20, 21, 7, 16, 2, 2, 21, 24, 3, 2, 2, 2, 22, 24, 5,
	6, 4, 2, 23, 17, 3, 2, 2, 2, 23, 22, 3, 2, 2, 2, 24, 38, 3, 2, 2, 2, 25,
	26, 12, 6, 2, 2, 26, 27, 7, 14, 2, 2, 27, 37, 5, 4, 3, 7, 28, 29, 12, 5,
	2, 2, 29, 37, 5, 4, 3, 6, 30, 31, 12, 9, 2, 2, 31, 37, 7, 11, 2, 2, 32,
	33, 12, 8, 2, 2, 33, 37, 7, 12, 2, 2, 34, 35, 12, 7, 2, 2, 35, 37, 7, 13,
	2, 2, 36, 25, 3, 2, 2, 2, 36, 28, 3, 2, 2, 2, 36, 30, 3, 2, 2, 2, 36, 32,
	3, 2, 2, 2, 36, 34, 3, 2, 2, 2, 37, 40, 3, 2, 2, 2, 38, 36, 3, 2, 2, 2,
	38, 39, 3, 2, 2, 2, 39, 5, 3, 2, 2, 2, 40, 38, 3, 2, 2, 2, 41, 58, 5, 8,
	5, 2, 42, 43, 5, 8, 5, 2, 43, 44, 5, 10, 6, 2, 44, 58, 3, 2, 2, 2, 45,
	46, 5, 8, 5, 2, 46, 47, 5, 10, 6, 2, 47, 48, 7, 9, 2, 2, 48, 49, 5, 12,
	7, 2, 49, 58, 3, 2, 2, 2, 50, 51, 5, 8, 5, 2, 51, 52, 5, 10, 6, 2, 52,
	53, 7, 9, 2, 2, 53, 54, 5, 12, 7, 2, 54, 55, 7, 10, 2, 2, 55, 56, 5, 12,
	7, 2, 56, 58, 3, 2, 2, 2, 57, 41, 3, 2, 2, 2, 57, 42, 3, 2, 2, 2, 57, 45,
	3, 2, 2, 2, 57, 50, 3, 2, 2, 2, 58, 7, 3, 2, 2, 2, 59, 62, 7, 4, 2, 2,
	60, 62, 7, 5, 2, 2, 61, 59, 3, 2, 2, 2, 61, 60, 3, 2, 2, 2, 62, 9, 3, 2,
	2, 2, 63, 67, 7, 6, 2, 2, 64, 67, 7, 7, 2, 2, 65, 67, 7, 8, 2, 2, 66, 63,
	3, 2, 2, 2, 66, 64, 3, 2, 2, 2, 66, 65, 3, 2, 2, 2, 67, 11, 3, 2, 2, 2,
	68, 71, 7, 4, 2, 2, 69, 71, 7, 5, 2, 2, 70, 68, 3, 2, 2, 2, 70, 69, 3,
	2, 2, 2, 71, 13, 3, 2, 2, 2, 9, 23, 36, 38, 57, 61, 66, 70,
}
var deserializer = antlr.NewATNDeserializer(nil)
var deserializedATN = deserializer.DeserializeFromUInt16(parserATN)

var literalNames = []string{
	"", "", "'0'", "", "", "", "", "'#'", "','", "'?'", "'+'", "'*'", "'|'",
	"'('", "')'",
}
var symbolicNames = []string{
	"", "WHITESPACE", "ZERO", "NUM", "WILDCARDAS", "LEGACYAS", "AS", "HASH",
	"COMMA", "QUESTIONMARK", "PLUS", "ASTERISK", "OR", "LPAR", "RPAR",
}

var ruleNames = []string{
	"start", "sequence", "onehop", "isd", "as", "iface",
}
var decisionToDFA = make([]*antlr.DFA, len(deserializedATN.DecisionToState))

func init() {
	for index, ds := range deserializedATN.DecisionToState {
		decisionToDFA[index] = antlr.NewDFA(ds, index)
	}
}

type SequenceParser struct {
	*antlr.BaseParser
}

func NewSequenceParser(input antlr.TokenStream) *SequenceParser {
	this := new(SequenceParser)

	this.BaseParser = antlr.NewBaseParser(input)

	this.Interpreter = antlr.NewParserATNSimulator(this, deserializedATN, decisionToDFA, antlr.NewPredictionContextCache())
	this.RuleNames = ruleNames
	this.LiteralNames = literalNames
	this.SymbolicNames = symbolicNames
	this.GrammarFileName = "Sequence.g4"

	return this
}

// SequenceParser tokens.
const (
	SequenceParserEOF          = antlr.TokenEOF
	SequenceParserWHITESPACE   = 1
	SequenceParserZERO         = 2
	SequenceParserNUM          = 3
	SequenceParserWILDCARDAS   = 4
	SequenceParserLEGACYAS     = 5
	SequenceParserAS           = 6
	SequenceParserHASH         = 7
	SequenceParserCOMMA        = 8
	SequenceParserQUESTIONMARK = 9
	SequenceParserPLUS         = 10
	SequenceParserASTERISK     = 11
	SequenceParserOR           = 12
	SequenceParserLPAR         = 13
	SequenceParserRPAR         = 14
)

// SequenceParser rules.
const (
	SequenceParserRULE_start    = 0
	SequenceParserRULE_sequence = 1
	SequenceParserRULE_onehop   = 2
	SequenceParserRULE_isd      = 3
	SequenceParserRULE_as       = 4
	SequenceParserRULE_iface    = 5
)

// IStartContext is an interface to support dynamic dispatch.
type IStartContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsStartContext differentiates from other interfaces.
	IsStartContext()
}

type StartContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyStartContext() *StartContext {
	var p = new(StartContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = SequenceParserRULE_start
	return p
}

func (*StartContext) IsStartContext() {}

func NewStartContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *StartContext {
	var p = new(StartContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = SequenceParserRULE_start

	return p
}

func (s *StartContext) GetParser() antlr.Parser { return s.parser }

func (s *StartContext) Sequence() ISequenceContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ISequenceContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ISequenceContext)
}

func (s *StartContext) EOF() antlr.TerminalNode {
	return s.GetToken(SequenceParserEOF, 0)
}

func (s *StartContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *StartContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *StartContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterStart(s)
	}
}

func (s *StartContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitStart(s)
	}
}

func (p *SequenceParser) Start() (localctx IStartContext) {
	localctx = NewStartContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 0, SequenceParserRULE_start)

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
		p.SetState(12)
		p.sequence(0)
	}
	{
		p.SetState(13)
		p.Match(SequenceParserEOF)
	}

	return localctx
}

// ISequenceContext is an interface to support dynamic dispatch.
type ISequenceContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsSequenceContext differentiates from other interfaces.
	IsSequenceContext()
}

type SequenceContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptySequenceContext() *SequenceContext {
	var p = new(SequenceContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = SequenceParserRULE_sequence
	return p
}

func (*SequenceContext) IsSequenceContext() {}

func NewSequenceContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *SequenceContext {
	var p = new(SequenceContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = SequenceParserRULE_sequence

	return p
}

func (s *SequenceContext) GetParser() antlr.Parser { return s.parser }

func (s *SequenceContext) CopyFrom(ctx *SequenceContext) {
	s.BaseParserRuleContext.CopyFrom(ctx.BaseParserRuleContext)
}

func (s *SequenceContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *SequenceContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

type OrContext struct {
	*SequenceContext
}

func NewOrContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *OrContext {
	var p = new(OrContext)

	p.SequenceContext = NewEmptySequenceContext()
	p.parser = parser
	p.CopyFrom(ctx.(*SequenceContext))

	return p
}

func (s *OrContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *OrContext) AllSequence() []ISequenceContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*ISequenceContext)(nil)).Elem())
	var tst = make([]ISequenceContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(ISequenceContext)
		}
	}

	return tst
}

func (s *OrContext) Sequence(i int) ISequenceContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ISequenceContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(ISequenceContext)
}

func (s *OrContext) OR() antlr.TerminalNode {
	return s.GetToken(SequenceParserOR, 0)
}

func (s *OrContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterOr(s)
	}
}

func (s *OrContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitOr(s)
	}
}

type ConcatenationContext struct {
	*SequenceContext
}

func NewConcatenationContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ConcatenationContext {
	var p = new(ConcatenationContext)

	p.SequenceContext = NewEmptySequenceContext()
	p.parser = parser
	p.CopyFrom(ctx.(*SequenceContext))

	return p
}

func (s *ConcatenationContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ConcatenationContext) AllSequence() []ISequenceContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*ISequenceContext)(nil)).Elem())
	var tst = make([]ISequenceContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(ISequenceContext)
		}
	}

	return tst
}

func (s *ConcatenationContext) Sequence(i int) ISequenceContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ISequenceContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(ISequenceContext)
}

func (s *ConcatenationContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterConcatenation(s)
	}
}

func (s *ConcatenationContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitConcatenation(s)
	}
}

type QuestionMarkContext struct {
	*SequenceContext
}

func NewQuestionMarkContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *QuestionMarkContext {
	var p = new(QuestionMarkContext)

	p.SequenceContext = NewEmptySequenceContext()
	p.parser = parser
	p.CopyFrom(ctx.(*SequenceContext))

	return p
}

func (s *QuestionMarkContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *QuestionMarkContext) Sequence() ISequenceContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ISequenceContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ISequenceContext)
}

func (s *QuestionMarkContext) QUESTIONMARK() antlr.TerminalNode {
	return s.GetToken(SequenceParserQUESTIONMARK, 0)
}

func (s *QuestionMarkContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterQuestionMark(s)
	}
}

func (s *QuestionMarkContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitQuestionMark(s)
	}
}

type HopContext struct {
	*SequenceContext
}

func NewHopContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *HopContext {
	var p = new(HopContext)

	p.SequenceContext = NewEmptySequenceContext()
	p.parser = parser
	p.CopyFrom(ctx.(*SequenceContext))

	return p
}

func (s *HopContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *HopContext) Onehop() IOnehopContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IOnehopContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IOnehopContext)
}

func (s *HopContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterHop(s)
	}
}

func (s *HopContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitHop(s)
	}
}

type PlusContext struct {
	*SequenceContext
}

func NewPlusContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *PlusContext {
	var p = new(PlusContext)

	p.SequenceContext = NewEmptySequenceContext()
	p.parser = parser
	p.CopyFrom(ctx.(*SequenceContext))

	return p
}

func (s *PlusContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *PlusContext) Sequence() ISequenceContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ISequenceContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ISequenceContext)
}

func (s *PlusContext) PLUS() antlr.TerminalNode {
	return s.GetToken(SequenceParserPLUS, 0)
}

func (s *PlusContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterPlus(s)
	}
}

func (s *PlusContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitPlus(s)
	}
}

type AsteriskContext struct {
	*SequenceContext
}

func NewAsteriskContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *AsteriskContext {
	var p = new(AsteriskContext)

	p.SequenceContext = NewEmptySequenceContext()
	p.parser = parser
	p.CopyFrom(ctx.(*SequenceContext))

	return p
}

func (s *AsteriskContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *AsteriskContext) Sequence() ISequenceContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ISequenceContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ISequenceContext)
}

func (s *AsteriskContext) ASTERISK() antlr.TerminalNode {
	return s.GetToken(SequenceParserASTERISK, 0)
}

func (s *AsteriskContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterAsterisk(s)
	}
}

func (s *AsteriskContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitAsterisk(s)
	}
}

type ParenthesesContext struct {
	*SequenceContext
}

func NewParenthesesContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ParenthesesContext {
	var p = new(ParenthesesContext)

	p.SequenceContext = NewEmptySequenceContext()
	p.parser = parser
	p.CopyFrom(ctx.(*SequenceContext))

	return p
}

func (s *ParenthesesContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ParenthesesContext) LPAR() antlr.TerminalNode {
	return s.GetToken(SequenceParserLPAR, 0)
}

func (s *ParenthesesContext) Sequence() ISequenceContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ISequenceContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ISequenceContext)
}

func (s *ParenthesesContext) RPAR() antlr.TerminalNode {
	return s.GetToken(SequenceParserRPAR, 0)
}

func (s *ParenthesesContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterParentheses(s)
	}
}

func (s *ParenthesesContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitParentheses(s)
	}
}

func (p *SequenceParser) Sequence() (localctx ISequenceContext) {
	return p.sequence(0)
}

func (p *SequenceParser) sequence(_p int) (localctx ISequenceContext) {
	var _parentctx antlr.ParserRuleContext = p.GetParserRuleContext()
	_parentState := p.GetState()
	localctx = NewSequenceContext(p, p.GetParserRuleContext(), _parentState)
	var _prevctx ISequenceContext = localctx
	var _ antlr.ParserRuleContext = _prevctx // TODO: To prevent unused variable warning.
	_startState := 2
	p.EnterRecursionRule(localctx, 2, SequenceParserRULE_sequence, _p)

	defer func() {
		p.UnrollRecursionContexts(_parentctx)
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

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	p.SetState(21)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case SequenceParserLPAR:
		localctx = NewParenthesesContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx

		{
			p.SetState(16)
			p.Match(SequenceParserLPAR)
		}
		{
			p.SetState(17)
			p.sequence(0)
		}
		{
			p.SetState(18)
			p.Match(SequenceParserRPAR)
		}

	case SequenceParserZERO, SequenceParserNUM:
		localctx = NewHopContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx
		{
			p.SetState(20)
			p.Onehop()
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}
	p.GetParserRuleContext().SetStop(p.GetTokenStream().LT(-1))
	p.SetState(36)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 2, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			if p.GetParseListeners() != nil {
				p.TriggerExitRuleEvent()
			}
			_prevctx = localctx
			p.SetState(34)
			p.GetErrorHandler().Sync(p)
			switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 1, p.GetParserRuleContext()) {
			case 1:
				localctx = NewOrContext(p, NewSequenceContext(p, _parentctx, _parentState))
				p.PushNewRecursionContext(localctx, _startState, SequenceParserRULE_sequence)
				p.SetState(23)

				if !(p.Precpred(p.GetParserRuleContext(), 4)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 4)", ""))
				}
				{
					p.SetState(24)
					p.Match(SequenceParserOR)
				}
				{
					p.SetState(25)
					p.sequence(5)
				}

			case 2:
				localctx = NewConcatenationContext(p, NewSequenceContext(p, _parentctx, _parentState))
				p.PushNewRecursionContext(localctx, _startState, SequenceParserRULE_sequence)
				p.SetState(26)

				if !(p.Precpred(p.GetParserRuleContext(), 3)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 3)", ""))
				}
				{
					p.SetState(27)
					p.sequence(4)
				}

			case 3:
				localctx = NewQuestionMarkContext(p, NewSequenceContext(p, _parentctx, _parentState))
				p.PushNewRecursionContext(localctx, _startState, SequenceParserRULE_sequence)
				p.SetState(28)

				if !(p.Precpred(p.GetParserRuleContext(), 7)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 7)", ""))
				}
				{
					p.SetState(29)
					p.Match(SequenceParserQUESTIONMARK)
				}

			case 4:
				localctx = NewPlusContext(p, NewSequenceContext(p, _parentctx, _parentState))
				p.PushNewRecursionContext(localctx, _startState, SequenceParserRULE_sequence)
				p.SetState(30)

				if !(p.Precpred(p.GetParserRuleContext(), 6)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 6)", ""))
				}
				{
					p.SetState(31)
					p.Match(SequenceParserPLUS)
				}

			case 5:
				localctx = NewAsteriskContext(p, NewSequenceContext(p, _parentctx, _parentState))
				p.PushNewRecursionContext(localctx, _startState, SequenceParserRULE_sequence)
				p.SetState(32)

				if !(p.Precpred(p.GetParserRuleContext(), 5)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 5)", ""))
				}
				{
					p.SetState(33)
					p.Match(SequenceParserASTERISK)
				}

			}

		}
		p.SetState(38)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 2, p.GetParserRuleContext())
	}

	return localctx
}

// IOnehopContext is an interface to support dynamic dispatch.
type IOnehopContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsOnehopContext differentiates from other interfaces.
	IsOnehopContext()
}

type OnehopContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyOnehopContext() *OnehopContext {
	var p = new(OnehopContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = SequenceParserRULE_onehop
	return p
}

func (*OnehopContext) IsOnehopContext() {}

func NewOnehopContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *OnehopContext {
	var p = new(OnehopContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = SequenceParserRULE_onehop

	return p
}

func (s *OnehopContext) GetParser() antlr.Parser { return s.parser }

func (s *OnehopContext) CopyFrom(ctx *OnehopContext) {
	s.BaseParserRuleContext.CopyFrom(ctx.BaseParserRuleContext)
}

func (s *OnehopContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *OnehopContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

type ISDASHopContext struct {
	*OnehopContext
}

func NewISDASHopContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ISDASHopContext {
	var p = new(ISDASHopContext)

	p.OnehopContext = NewEmptyOnehopContext()
	p.parser = parser
	p.CopyFrom(ctx.(*OnehopContext))

	return p
}

func (s *ISDASHopContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ISDASHopContext) Isd() IIsdContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IIsdContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IIsdContext)
}

func (s *ISDASHopContext) As() IAsContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IAsContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IAsContext)
}

func (s *ISDASHopContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterISDASHop(s)
	}
}

func (s *ISDASHopContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitISDASHop(s)
	}
}

type ISDASIFIFHopContext struct {
	*OnehopContext
}

func NewISDASIFIFHopContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ISDASIFIFHopContext {
	var p = new(ISDASIFIFHopContext)

	p.OnehopContext = NewEmptyOnehopContext()
	p.parser = parser
	p.CopyFrom(ctx.(*OnehopContext))

	return p
}

func (s *ISDASIFIFHopContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ISDASIFIFHopContext) Isd() IIsdContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IIsdContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IIsdContext)
}

func (s *ISDASIFIFHopContext) As() IAsContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IAsContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IAsContext)
}

func (s *ISDASIFIFHopContext) HASH() antlr.TerminalNode {
	return s.GetToken(SequenceParserHASH, 0)
}

func (s *ISDASIFIFHopContext) AllIface() []IIfaceContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*IIfaceContext)(nil)).Elem())
	var tst = make([]IIfaceContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(IIfaceContext)
		}
	}

	return tst
}

func (s *ISDASIFIFHopContext) Iface(i int) IIfaceContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IIfaceContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(IIfaceContext)
}

func (s *ISDASIFIFHopContext) COMMA() antlr.TerminalNode {
	return s.GetToken(SequenceParserCOMMA, 0)
}

func (s *ISDASIFIFHopContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterISDASIFIFHop(s)
	}
}

func (s *ISDASIFIFHopContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitISDASIFIFHop(s)
	}
}

type ISDHopContext struct {
	*OnehopContext
}

func NewISDHopContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ISDHopContext {
	var p = new(ISDHopContext)

	p.OnehopContext = NewEmptyOnehopContext()
	p.parser = parser
	p.CopyFrom(ctx.(*OnehopContext))

	return p
}

func (s *ISDHopContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ISDHopContext) Isd() IIsdContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IIsdContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IIsdContext)
}

func (s *ISDHopContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterISDHop(s)
	}
}

func (s *ISDHopContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitISDHop(s)
	}
}

type ISDASIFHopContext struct {
	*OnehopContext
}

func NewISDASIFHopContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ISDASIFHopContext {
	var p = new(ISDASIFHopContext)

	p.OnehopContext = NewEmptyOnehopContext()
	p.parser = parser
	p.CopyFrom(ctx.(*OnehopContext))

	return p
}

func (s *ISDASIFHopContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ISDASIFHopContext) Isd() IIsdContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IIsdContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IIsdContext)
}

func (s *ISDASIFHopContext) As() IAsContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IAsContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IAsContext)
}

func (s *ISDASIFHopContext) HASH() antlr.TerminalNode {
	return s.GetToken(SequenceParserHASH, 0)
}

func (s *ISDASIFHopContext) Iface() IIfaceContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IIfaceContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IIfaceContext)
}

func (s *ISDASIFHopContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterISDASIFHop(s)
	}
}

func (s *ISDASIFHopContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitISDASIFHop(s)
	}
}

func (p *SequenceParser) Onehop() (localctx IOnehopContext) {
	localctx = NewOnehopContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 4, SequenceParserRULE_onehop)

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

	p.SetState(55)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 3, p.GetParserRuleContext()) {
	case 1:
		localctx = NewISDHopContext(p, localctx)
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(39)
			p.Isd()
		}

	case 2:
		localctx = NewISDASHopContext(p, localctx)
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(40)
			p.Isd()
		}
		{
			p.SetState(41)
			p.As()
		}

	case 3:
		localctx = NewISDASIFHopContext(p, localctx)
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(43)
			p.Isd()
		}
		{
			p.SetState(44)
			p.As()
		}
		{
			p.SetState(45)
			p.Match(SequenceParserHASH)
		}
		{
			p.SetState(46)
			p.Iface()
		}

	case 4:
		localctx = NewISDASIFIFHopContext(p, localctx)
		p.EnterOuterAlt(localctx, 4)
		{
			p.SetState(48)
			p.Isd()
		}
		{
			p.SetState(49)
			p.As()
		}
		{
			p.SetState(50)
			p.Match(SequenceParserHASH)
		}
		{
			p.SetState(51)
			p.Iface()
		}
		{
			p.SetState(52)
			p.Match(SequenceParserCOMMA)
		}
		{
			p.SetState(53)
			p.Iface()
		}

	}

	return localctx
}

// IIsdContext is an interface to support dynamic dispatch.
type IIsdContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsIsdContext differentiates from other interfaces.
	IsIsdContext()
}

type IsdContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyIsdContext() *IsdContext {
	var p = new(IsdContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = SequenceParserRULE_isd
	return p
}

func (*IsdContext) IsIsdContext() {}

func NewIsdContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *IsdContext {
	var p = new(IsdContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = SequenceParserRULE_isd

	return p
}

func (s *IsdContext) GetParser() antlr.Parser { return s.parser }

func (s *IsdContext) CopyFrom(ctx *IsdContext) {
	s.BaseParserRuleContext.CopyFrom(ctx.BaseParserRuleContext)
}

func (s *IsdContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *IsdContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

type WildcardISDContext struct {
	*IsdContext
}

func NewWildcardISDContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *WildcardISDContext {
	var p = new(WildcardISDContext)

	p.IsdContext = NewEmptyIsdContext()
	p.parser = parser
	p.CopyFrom(ctx.(*IsdContext))

	return p
}

func (s *WildcardISDContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *WildcardISDContext) ZERO() antlr.TerminalNode {
	return s.GetToken(SequenceParserZERO, 0)
}

func (s *WildcardISDContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterWildcardISD(s)
	}
}

func (s *WildcardISDContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitWildcardISD(s)
	}
}

type ISDContext struct {
	*IsdContext
}

func NewISDContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ISDContext {
	var p = new(ISDContext)

	p.IsdContext = NewEmptyIsdContext()
	p.parser = parser
	p.CopyFrom(ctx.(*IsdContext))

	return p
}

func (s *ISDContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ISDContext) NUM() antlr.TerminalNode {
	return s.GetToken(SequenceParserNUM, 0)
}

func (s *ISDContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterISD(s)
	}
}

func (s *ISDContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitISD(s)
	}
}

func (p *SequenceParser) Isd() (localctx IIsdContext) {
	localctx = NewIsdContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 6, SequenceParserRULE_isd)

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

	p.SetState(59)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case SequenceParserZERO:
		localctx = NewWildcardISDContext(p, localctx)
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(57)
			p.Match(SequenceParserZERO)
		}

	case SequenceParserNUM:
		localctx = NewISDContext(p, localctx)
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(58)
			p.Match(SequenceParserNUM)
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// IAsContext is an interface to support dynamic dispatch.
type IAsContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsAsContext differentiates from other interfaces.
	IsAsContext()
}

type AsContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyAsContext() *AsContext {
	var p = new(AsContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = SequenceParserRULE_as
	return p
}

func (*AsContext) IsAsContext() {}

func NewAsContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *AsContext {
	var p = new(AsContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = SequenceParserRULE_as

	return p
}

func (s *AsContext) GetParser() antlr.Parser { return s.parser }

func (s *AsContext) CopyFrom(ctx *AsContext) {
	s.BaseParserRuleContext.CopyFrom(ctx.BaseParserRuleContext)
}

func (s *AsContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *AsContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

type ASContext struct {
	*AsContext
}

func NewASContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ASContext {
	var p = new(ASContext)

	p.AsContext = NewEmptyAsContext()
	p.parser = parser
	p.CopyFrom(ctx.(*AsContext))

	return p
}

func (s *ASContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ASContext) AS() antlr.TerminalNode {
	return s.GetToken(SequenceParserAS, 0)
}

func (s *ASContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterAS(s)
	}
}

func (s *ASContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitAS(s)
	}
}

type LegacyASContext struct {
	*AsContext
}

func NewLegacyASContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *LegacyASContext {
	var p = new(LegacyASContext)

	p.AsContext = NewEmptyAsContext()
	p.parser = parser
	p.CopyFrom(ctx.(*AsContext))

	return p
}

func (s *LegacyASContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *LegacyASContext) LEGACYAS() antlr.TerminalNode {
	return s.GetToken(SequenceParserLEGACYAS, 0)
}

func (s *LegacyASContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterLegacyAS(s)
	}
}

func (s *LegacyASContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitLegacyAS(s)
	}
}

type WildcardASContext struct {
	*AsContext
}

func NewWildcardASContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *WildcardASContext {
	var p = new(WildcardASContext)

	p.AsContext = NewEmptyAsContext()
	p.parser = parser
	p.CopyFrom(ctx.(*AsContext))

	return p
}

func (s *WildcardASContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *WildcardASContext) WILDCARDAS() antlr.TerminalNode {
	return s.GetToken(SequenceParserWILDCARDAS, 0)
}

func (s *WildcardASContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterWildcardAS(s)
	}
}

func (s *WildcardASContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitWildcardAS(s)
	}
}

func (p *SequenceParser) As() (localctx IAsContext) {
	localctx = NewAsContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 8, SequenceParserRULE_as)

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

	p.SetState(64)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case SequenceParserWILDCARDAS:
		localctx = NewWildcardASContext(p, localctx)
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(61)
			p.Match(SequenceParserWILDCARDAS)
		}

	case SequenceParserLEGACYAS:
		localctx = NewLegacyASContext(p, localctx)
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(62)
			p.Match(SequenceParserLEGACYAS)
		}

	case SequenceParserAS:
		localctx = NewASContext(p, localctx)
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(63)
			p.Match(SequenceParserAS)
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// IIfaceContext is an interface to support dynamic dispatch.
type IIfaceContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsIfaceContext differentiates from other interfaces.
	IsIfaceContext()
}

type IfaceContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyIfaceContext() *IfaceContext {
	var p = new(IfaceContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = SequenceParserRULE_iface
	return p
}

func (*IfaceContext) IsIfaceContext() {}

func NewIfaceContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *IfaceContext {
	var p = new(IfaceContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = SequenceParserRULE_iface

	return p
}

func (s *IfaceContext) GetParser() antlr.Parser { return s.parser }

func (s *IfaceContext) CopyFrom(ctx *IfaceContext) {
	s.BaseParserRuleContext.CopyFrom(ctx.BaseParserRuleContext)
}

func (s *IfaceContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *IfaceContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

type IFaceContext struct {
	*IfaceContext
}

func NewIFaceContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *IFaceContext {
	var p = new(IFaceContext)

	p.IfaceContext = NewEmptyIfaceContext()
	p.parser = parser
	p.CopyFrom(ctx.(*IfaceContext))

	return p
}

func (s *IFaceContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *IFaceContext) NUM() antlr.TerminalNode {
	return s.GetToken(SequenceParserNUM, 0)
}

func (s *IFaceContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterIFace(s)
	}
}

func (s *IFaceContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitIFace(s)
	}
}

type WildcardIFaceContext struct {
	*IfaceContext
}

func NewWildcardIFaceContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *WildcardIFaceContext {
	var p = new(WildcardIFaceContext)

	p.IfaceContext = NewEmptyIfaceContext()
	p.parser = parser
	p.CopyFrom(ctx.(*IfaceContext))

	return p
}

func (s *WildcardIFaceContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *WildcardIFaceContext) ZERO() antlr.TerminalNode {
	return s.GetToken(SequenceParserZERO, 0)
}

func (s *WildcardIFaceContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.EnterWildcardIFace(s)
	}
}

func (s *WildcardIFaceContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(SequenceListener); ok {
		listenerT.ExitWildcardIFace(s)
	}
}

func (p *SequenceParser) Iface() (localctx IIfaceContext) {
	localctx = NewIfaceContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 10, SequenceParserRULE_iface)

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

	p.SetState(68)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case SequenceParserZERO:
		localctx = NewWildcardIFaceContext(p, localctx)
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(66)
			p.Match(SequenceParserZERO)
		}

	case SequenceParserNUM:
		localctx = NewIFaceContext(p, localctx)
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(67)
			p.Match(SequenceParserNUM)
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

func (p *SequenceParser) Sempred(localctx antlr.RuleContext, ruleIndex, predIndex int) bool {
	switch ruleIndex {
	case 1:
		var t *SequenceContext = nil
		if localctx != nil {
			t = localctx.(*SequenceContext)
		}
		return p.Sequence_Sempred(t, predIndex)

	default:
		panic("No predicate with index: " + fmt.Sprint(ruleIndex))
	}
}

func (p *SequenceParser) Sequence_Sempred(localctx antlr.RuleContext, predIndex int) bool {
	switch predIndex {
	case 0:
		return p.Precpred(p.GetParserRuleContext(), 4)

	case 1:
		return p.Precpred(p.GetParserRuleContext(), 3)

	case 2:
		return p.Precpred(p.GetParserRuleContext(), 7)

	case 3:
		return p.Precpred(p.GetParserRuleContext(), 6)

	case 4:
		return p.Precpred(p.GetParserRuleContext(), 5)

	default:
		panic("No predicate with index: " + fmt.Sprint(predIndex))
	}
}
