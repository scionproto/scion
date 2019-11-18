// Code generated from TrafficClass.g4 by ANTLR 4.7.1. DO NOT EDIT.

package traffic_class // TrafficClass
import "github.com/antlr/antlr4/runtime/Go/antlr"

// BaseTrafficClassListener is a complete listener for a parse tree produced by TrafficClassParser.
type BaseTrafficClassListener struct{}

var _ TrafficClassListener = &BaseTrafficClassListener{}

// VisitTerminal is called when a terminal node is visited.
func (s *BaseTrafficClassListener) VisitTerminal(node antlr.TerminalNode) {}

// VisitErrorNode is called when an error node is visited.
func (s *BaseTrafficClassListener) VisitErrorNode(node antlr.ErrorNode) {}

// EnterEveryRule is called when any rule is entered.
func (s *BaseTrafficClassListener) EnterEveryRule(ctx antlr.ParserRuleContext) {}

// ExitEveryRule is called when any rule is exited.
func (s *BaseTrafficClassListener) ExitEveryRule(ctx antlr.ParserRuleContext) {}

// EnterMatchSrc is called when production matchSrc is entered.
func (s *BaseTrafficClassListener) EnterMatchSrc(ctx *MatchSrcContext) {}

// ExitMatchSrc is called when production matchSrc is exited.
func (s *BaseTrafficClassListener) ExitMatchSrc(ctx *MatchSrcContext) {}

// EnterMatchDst is called when production matchDst is entered.
func (s *BaseTrafficClassListener) EnterMatchDst(ctx *MatchDstContext) {}

// ExitMatchDst is called when production matchDst is exited.
func (s *BaseTrafficClassListener) ExitMatchDst(ctx *MatchDstContext) {}

// EnterMatchDSCP is called when production matchDSCP is entered.
func (s *BaseTrafficClassListener) EnterMatchDSCP(ctx *MatchDSCPContext) {}

// ExitMatchDSCP is called when production matchDSCP is exited.
func (s *BaseTrafficClassListener) ExitMatchDSCP(ctx *MatchDSCPContext) {}

// EnterMatchTOS is called when production matchTOS is entered.
func (s *BaseTrafficClassListener) EnterMatchTOS(ctx *MatchTOSContext) {}

// ExitMatchTOS is called when production matchTOS is exited.
func (s *BaseTrafficClassListener) ExitMatchTOS(ctx *MatchTOSContext) {}

// EnterCondCls is called when production condCls is entered.
func (s *BaseTrafficClassListener) EnterCondCls(ctx *CondClsContext) {}

// ExitCondCls is called when production condCls is exited.
func (s *BaseTrafficClassListener) ExitCondCls(ctx *CondClsContext) {}

// EnterCondAny is called when production condAny is entered.
func (s *BaseTrafficClassListener) EnterCondAny(ctx *CondAnyContext) {}

// ExitCondAny is called when production condAny is exited.
func (s *BaseTrafficClassListener) ExitCondAny(ctx *CondAnyContext) {}

// EnterCondAll is called when production condAll is entered.
func (s *BaseTrafficClassListener) EnterCondAll(ctx *CondAllContext) {}

// ExitCondAll is called when production condAll is exited.
func (s *BaseTrafficClassListener) ExitCondAll(ctx *CondAllContext) {}

// EnterCondNot is called when production condNot is entered.
func (s *BaseTrafficClassListener) EnterCondNot(ctx *CondNotContext) {}

// ExitCondNot is called when production condNot is exited.
func (s *BaseTrafficClassListener) ExitCondNot(ctx *CondNotContext) {}

// EnterCondBool is called when production condBool is entered.
func (s *BaseTrafficClassListener) EnterCondBool(ctx *CondBoolContext) {}

// ExitCondBool is called when production condBool is exited.
func (s *BaseTrafficClassListener) ExitCondBool(ctx *CondBoolContext) {}

// EnterCondIPv4 is called when production condIPv4 is entered.
func (s *BaseTrafficClassListener) EnterCondIPv4(ctx *CondIPv4Context) {}

// ExitCondIPv4 is called when production condIPv4 is exited.
func (s *BaseTrafficClassListener) ExitCondIPv4(ctx *CondIPv4Context) {}

// EnterCond is called when production cond is entered.
func (s *BaseTrafficClassListener) EnterCond(ctx *CondContext) {}

// ExitCond is called when production cond is exited.
func (s *BaseTrafficClassListener) ExitCond(ctx *CondContext) {}

// EnterTrafficClass is called when production trafficClass is entered.
func (s *BaseTrafficClassListener) EnterTrafficClass(ctx *TrafficClassContext) {}

// ExitTrafficClass is called when production trafficClass is exited.
func (s *BaseTrafficClassListener) ExitTrafficClass(ctx *TrafficClassContext) {}
