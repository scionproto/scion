// Code generated from TrafficClass.g4 by ANTLR 4.7.1. DO NOT EDIT.

package traffic_class // TrafficClass
import "github.com/antlr/antlr4/runtime/Go/antlr"

// TrafficClassListener is a complete listener for a parse tree produced by TrafficClassParser.
type TrafficClassListener interface {
	antlr.ParseTreeListener

	// EnterMatchSrc is called when entering the matchSrc production.
	EnterMatchSrc(c *MatchSrcContext)

	// EnterMatchDst is called when entering the matchDst production.
	EnterMatchDst(c *MatchDstContext)

	// EnterMatchDSCP is called when entering the matchDSCP production.
	EnterMatchDSCP(c *MatchDSCPContext)

	// EnterMatchTOS is called when entering the matchTOS production.
	EnterMatchTOS(c *MatchTOSContext)

	// EnterCondCls is called when entering the condCls production.
	EnterCondCls(c *CondClsContext)

	// EnterCondAny is called when entering the condAny production.
	EnterCondAny(c *CondAnyContext)

	// EnterCondAll is called when entering the condAll production.
	EnterCondAll(c *CondAllContext)

	// EnterCondNot is called when entering the condNot production.
	EnterCondNot(c *CondNotContext)

	// EnterCondBool is called when entering the condBool production.
	EnterCondBool(c *CondBoolContext)

	// EnterCondIPv4 is called when entering the condIPv4 production.
	EnterCondIPv4(c *CondIPv4Context)

	// EnterCond is called when entering the cond production.
	EnterCond(c *CondContext)

	// EnterTrafficClass is called when entering the trafficClass production.
	EnterTrafficClass(c *TrafficClassContext)

	// ExitMatchSrc is called when exiting the matchSrc production.
	ExitMatchSrc(c *MatchSrcContext)

	// ExitMatchDst is called when exiting the matchDst production.
	ExitMatchDst(c *MatchDstContext)

	// ExitMatchDSCP is called when exiting the matchDSCP production.
	ExitMatchDSCP(c *MatchDSCPContext)

	// ExitMatchTOS is called when exiting the matchTOS production.
	ExitMatchTOS(c *MatchTOSContext)

	// ExitCondCls is called when exiting the condCls production.
	ExitCondCls(c *CondClsContext)

	// ExitCondAny is called when exiting the condAny production.
	ExitCondAny(c *CondAnyContext)

	// ExitCondAll is called when exiting the condAll production.
	ExitCondAll(c *CondAllContext)

	// ExitCondNot is called when exiting the condNot production.
	ExitCondNot(c *CondNotContext)

	// ExitCondBool is called when exiting the condBool production.
	ExitCondBool(c *CondBoolContext)

	// ExitCondIPv4 is called when exiting the condIPv4 production.
	ExitCondIPv4(c *CondIPv4Context)

	// ExitCond is called when exiting the cond production.
	ExitCond(c *CondContext)

	// ExitTrafficClass is called when exiting the trafficClass production.
	ExitTrafficClass(c *TrafficClassContext)
}
