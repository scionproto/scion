// Code generated from Sequence.g4 by ANTLR 4.7.1. DO NOT EDIT.

package sequence // Sequence
import "github.com/antlr/antlr4/runtime/Go/antlr"

// BaseSequenceListener is a complete listener for a parse tree produced by SequenceParser.
type BaseSequenceListener struct{}

var _ SequenceListener = &BaseSequenceListener{}

// VisitTerminal is called when a terminal node is visited.
func (s *BaseSequenceListener) VisitTerminal(node antlr.TerminalNode) {}

// VisitErrorNode is called when an error node is visited.
func (s *BaseSequenceListener) VisitErrorNode(node antlr.ErrorNode) {}

// EnterEveryRule is called when any rule is entered.
func (s *BaseSequenceListener) EnterEveryRule(ctx antlr.ParserRuleContext) {}

// ExitEveryRule is called when any rule is exited.
func (s *BaseSequenceListener) ExitEveryRule(ctx antlr.ParserRuleContext) {}

// EnterStart is called when production start is entered.
func (s *BaseSequenceListener) EnterStart(ctx *StartContext) {}

// ExitStart is called when production start is exited.
func (s *BaseSequenceListener) ExitStart(ctx *StartContext) {}

// EnterOr is called when production Or is entered.
func (s *BaseSequenceListener) EnterOr(ctx *OrContext) {}

// ExitOr is called when production Or is exited.
func (s *BaseSequenceListener) ExitOr(ctx *OrContext) {}

// EnterConcatenation is called when production Concatenation is entered.
func (s *BaseSequenceListener) EnterConcatenation(ctx *ConcatenationContext) {}

// ExitConcatenation is called when production Concatenation is exited.
func (s *BaseSequenceListener) ExitConcatenation(ctx *ConcatenationContext) {}

// EnterQuestionMark is called when production QuestionMark is entered.
func (s *BaseSequenceListener) EnterQuestionMark(ctx *QuestionMarkContext) {}

// ExitQuestionMark is called when production QuestionMark is exited.
func (s *BaseSequenceListener) ExitQuestionMark(ctx *QuestionMarkContext) {}

// EnterHop is called when production Hop is entered.
func (s *BaseSequenceListener) EnterHop(ctx *HopContext) {}

// ExitHop is called when production Hop is exited.
func (s *BaseSequenceListener) ExitHop(ctx *HopContext) {}

// EnterPlus is called when production Plus is entered.
func (s *BaseSequenceListener) EnterPlus(ctx *PlusContext) {}

// ExitPlus is called when production Plus is exited.
func (s *BaseSequenceListener) ExitPlus(ctx *PlusContext) {}

// EnterAsterisk is called when production Asterisk is entered.
func (s *BaseSequenceListener) EnterAsterisk(ctx *AsteriskContext) {}

// ExitAsterisk is called when production Asterisk is exited.
func (s *BaseSequenceListener) ExitAsterisk(ctx *AsteriskContext) {}

// EnterParentheses is called when production Parentheses is entered.
func (s *BaseSequenceListener) EnterParentheses(ctx *ParenthesesContext) {}

// ExitParentheses is called when production Parentheses is exited.
func (s *BaseSequenceListener) ExitParentheses(ctx *ParenthesesContext) {}

// EnterISDHop is called when production ISDHop is entered.
func (s *BaseSequenceListener) EnterISDHop(ctx *ISDHopContext) {}

// ExitISDHop is called when production ISDHop is exited.
func (s *BaseSequenceListener) ExitISDHop(ctx *ISDHopContext) {}

// EnterISDASHop is called when production ISDASHop is entered.
func (s *BaseSequenceListener) EnterISDASHop(ctx *ISDASHopContext) {}

// ExitISDASHop is called when production ISDASHop is exited.
func (s *BaseSequenceListener) ExitISDASHop(ctx *ISDASHopContext) {}

// EnterISDASIFHop is called when production ISDASIFHop is entered.
func (s *BaseSequenceListener) EnterISDASIFHop(ctx *ISDASIFHopContext) {}

// ExitISDASIFHop is called when production ISDASIFHop is exited.
func (s *BaseSequenceListener) ExitISDASIFHop(ctx *ISDASIFHopContext) {}

// EnterISDASIFIFHop is called when production ISDASIFIFHop is entered.
func (s *BaseSequenceListener) EnterISDASIFIFHop(ctx *ISDASIFIFHopContext) {}

// ExitISDASIFIFHop is called when production ISDASIFIFHop is exited.
func (s *BaseSequenceListener) ExitISDASIFIFHop(ctx *ISDASIFIFHopContext) {}

// EnterWildcardISD is called when production WildcardISD is entered.
func (s *BaseSequenceListener) EnterWildcardISD(ctx *WildcardISDContext) {}

// ExitWildcardISD is called when production WildcardISD is exited.
func (s *BaseSequenceListener) ExitWildcardISD(ctx *WildcardISDContext) {}

// EnterISD is called when production ISD is entered.
func (s *BaseSequenceListener) EnterISD(ctx *ISDContext) {}

// ExitISD is called when production ISD is exited.
func (s *BaseSequenceListener) ExitISD(ctx *ISDContext) {}

// EnterWildcardAS is called when production WildcardAS is entered.
func (s *BaseSequenceListener) EnterWildcardAS(ctx *WildcardASContext) {}

// ExitWildcardAS is called when production WildcardAS is exited.
func (s *BaseSequenceListener) ExitWildcardAS(ctx *WildcardASContext) {}

// EnterLegacyAS is called when production LegacyAS is entered.
func (s *BaseSequenceListener) EnterLegacyAS(ctx *LegacyASContext) {}

// ExitLegacyAS is called when production LegacyAS is exited.
func (s *BaseSequenceListener) ExitLegacyAS(ctx *LegacyASContext) {}

// EnterAS is called when production AS is entered.
func (s *BaseSequenceListener) EnterAS(ctx *ASContext) {}

// ExitAS is called when production AS is exited.
func (s *BaseSequenceListener) ExitAS(ctx *ASContext) {}

// EnterWildcardIFace is called when production WildcardIFace is entered.
func (s *BaseSequenceListener) EnterWildcardIFace(ctx *WildcardIFaceContext) {}

// ExitWildcardIFace is called when production WildcardIFace is exited.
func (s *BaseSequenceListener) ExitWildcardIFace(ctx *WildcardIFaceContext) {}

// EnterIFace is called when production IFace is entered.
func (s *BaseSequenceListener) EnterIFace(ctx *IFaceContext) {}

// ExitIFace is called when production IFace is exited.
func (s *BaseSequenceListener) ExitIFace(ctx *IFaceContext) {}
