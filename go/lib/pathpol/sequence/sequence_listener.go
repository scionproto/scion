// Code generated from Sequence.g4 by ANTLR 4.7.1. DO NOT EDIT.

package sequence // Sequence
import "github.com/antlr/antlr4/runtime/Go/antlr"

// SequenceListener is a complete listener for a parse tree produced by SequenceParser.
type SequenceListener interface {
	antlr.ParseTreeListener

	// EnterStart is called when entering the start production.
	EnterStart(c *StartContext)

	// EnterOr is called when entering the Or production.
	EnterOr(c *OrContext)

	// EnterConcatenation is called when entering the Concatenation production.
	EnterConcatenation(c *ConcatenationContext)

	// EnterQuestionMark is called when entering the QuestionMark production.
	EnterQuestionMark(c *QuestionMarkContext)

	// EnterHop is called when entering the Hop production.
	EnterHop(c *HopContext)

	// EnterPlus is called when entering the Plus production.
	EnterPlus(c *PlusContext)

	// EnterAsterisk is called when entering the Asterisk production.
	EnterAsterisk(c *AsteriskContext)

	// EnterParentheses is called when entering the Parentheses production.
	EnterParentheses(c *ParenthesesContext)

	// EnterISDHop is called when entering the ISDHop production.
	EnterISDHop(c *ISDHopContext)

	// EnterISDASHop is called when entering the ISDASHop production.
	EnterISDASHop(c *ISDASHopContext)

	// EnterISDASIFHop is called when entering the ISDASIFHop production.
	EnterISDASIFHop(c *ISDASIFHopContext)

	// EnterISDASIFIFHop is called when entering the ISDASIFIFHop production.
	EnterISDASIFIFHop(c *ISDASIFIFHopContext)

	// EnterWildcardISD is called when entering the WildcardISD production.
	EnterWildcardISD(c *WildcardISDContext)

	// EnterISD is called when entering the ISD production.
	EnterISD(c *ISDContext)

	// EnterWildcardAS is called when entering the WildcardAS production.
	EnterWildcardAS(c *WildcardASContext)

	// EnterLegacyAS is called when entering the LegacyAS production.
	EnterLegacyAS(c *LegacyASContext)

	// EnterAS is called when entering the AS production.
	EnterAS(c *ASContext)

	// EnterWildcardIFace is called when entering the WildcardIFace production.
	EnterWildcardIFace(c *WildcardIFaceContext)

	// EnterIFace is called when entering the IFace production.
	EnterIFace(c *IFaceContext)

	// ExitStart is called when exiting the start production.
	ExitStart(c *StartContext)

	// ExitOr is called when exiting the Or production.
	ExitOr(c *OrContext)

	// ExitConcatenation is called when exiting the Concatenation production.
	ExitConcatenation(c *ConcatenationContext)

	// ExitQuestionMark is called when exiting the QuestionMark production.
	ExitQuestionMark(c *QuestionMarkContext)

	// ExitHop is called when exiting the Hop production.
	ExitHop(c *HopContext)

	// ExitPlus is called when exiting the Plus production.
	ExitPlus(c *PlusContext)

	// ExitAsterisk is called when exiting the Asterisk production.
	ExitAsterisk(c *AsteriskContext)

	// ExitParentheses is called when exiting the Parentheses production.
	ExitParentheses(c *ParenthesesContext)

	// ExitISDHop is called when exiting the ISDHop production.
	ExitISDHop(c *ISDHopContext)

	// ExitISDASHop is called when exiting the ISDASHop production.
	ExitISDASHop(c *ISDASHopContext)

	// ExitISDASIFHop is called when exiting the ISDASIFHop production.
	ExitISDASIFHop(c *ISDASIFHopContext)

	// ExitISDASIFIFHop is called when exiting the ISDASIFIFHop production.
	ExitISDASIFIFHop(c *ISDASIFIFHopContext)

	// ExitWildcardISD is called when exiting the WildcardISD production.
	ExitWildcardISD(c *WildcardISDContext)

	// ExitISD is called when exiting the ISD production.
	ExitISD(c *ISDContext)

	// ExitWildcardAS is called when exiting the WildcardAS production.
	ExitWildcardAS(c *WildcardASContext)

	// ExitLegacyAS is called when exiting the LegacyAS production.
	ExitLegacyAS(c *LegacyASContext)

	// ExitAS is called when exiting the AS production.
	ExitAS(c *ASContext)

	// ExitWildcardIFace is called when exiting the WildcardIFace production.
	ExitWildcardIFace(c *WildcardIFaceContext)

	// ExitIFace is called when exiting the IFace production.
	ExitIFace(c *IFaceContext)
}
