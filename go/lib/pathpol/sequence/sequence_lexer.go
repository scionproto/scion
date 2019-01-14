// Code generated from Sequence.g4 by ANTLR 4.7.1. DO NOT EDIT.

package sequence

import (
	"fmt"
	"unicode"

	"github.com/antlr/antlr4/runtime/Go/antlr"
)

// Suppress unused import error
var _ = fmt.Printf
var _ = unicode.IsLetter

var serializedLexerAtn = []uint16{
	3, 24715, 42794, 33075, 47597, 16764, 15335, 30598, 22884, 2, 16, 88, 8,
	1, 4, 2, 9, 2, 4, 3, 9, 3, 4, 4, 9, 4, 4, 5, 9, 5, 4, 6, 9, 6, 4, 7, 9,
	7, 4, 8, 9, 8, 4, 9, 9, 9, 4, 10, 9, 10, 4, 11, 9, 11, 4, 12, 9, 12, 4,
	13, 9, 13, 4, 14, 9, 14, 4, 15, 9, 15, 4, 16, 9, 16, 3, 2, 3, 2, 7, 2,
	36, 10, 2, 12, 2, 14, 2, 39, 11, 2, 3, 2, 5, 2, 42, 10, 2, 3, 3, 6, 3,
	45, 10, 3, 13, 3, 14, 3, 46, 3, 3, 3, 3, 3, 4, 3, 4, 3, 5, 3, 5, 7, 5,
	55, 10, 5, 12, 5, 14, 5, 58, 11, 5, 3, 6, 3, 6, 3, 6, 3, 7, 3, 7, 3, 7,
	3, 8, 3, 8, 3, 8, 3, 8, 3, 8, 3, 8, 3, 8, 3, 9, 3, 9, 3, 10, 3, 10, 3,
	11, 3, 11, 3, 12, 3, 12, 3, 13, 3, 13, 3, 14, 3, 14, 3, 15, 3, 15, 3, 16,
	3, 16, 2, 2, 17, 3, 2, 5, 3, 7, 4, 9, 5, 11, 6, 13, 7, 15, 8, 17, 9, 19,
	10, 21, 11, 23, 12, 25, 13, 27, 14, 29, 15, 31, 16, 3, 2, 7, 5, 2, 51,
	59, 67, 72, 99, 104, 5, 2, 50, 59, 67, 72, 99, 104, 5, 2, 11, 12, 15, 15,
	34, 34, 3, 2, 51, 59, 3, 2, 50, 59, 2, 90, 2, 5, 3, 2, 2, 2, 2, 7, 3, 2,
	2, 2, 2, 9, 3, 2, 2, 2, 2, 11, 3, 2, 2, 2, 2, 13, 3, 2, 2, 2, 2, 15, 3,
	2, 2, 2, 2, 17, 3, 2, 2, 2, 2, 19, 3, 2, 2, 2, 2, 21, 3, 2, 2, 2, 2, 23,
	3, 2, 2, 2, 2, 25, 3, 2, 2, 2, 2, 27, 3, 2, 2, 2, 2, 29, 3, 2, 2, 2, 2,
	31, 3, 2, 2, 2, 3, 41, 3, 2, 2, 2, 5, 44, 3, 2, 2, 2, 7, 50, 3, 2, 2, 2,
	9, 52, 3, 2, 2, 2, 11, 59, 3, 2, 2, 2, 13, 62, 3, 2, 2, 2, 15, 65, 3, 2,
	2, 2, 17, 72, 3, 2, 2, 2, 19, 74, 3, 2, 2, 2, 21, 76, 3, 2, 2, 2, 23, 78,
	3, 2, 2, 2, 25, 80, 3, 2, 2, 2, 27, 82, 3, 2, 2, 2, 29, 84, 3, 2, 2, 2,
	31, 86, 3, 2, 2, 2, 33, 37, 9, 2, 2, 2, 34, 36, 9, 3, 2, 2, 35, 34, 3,
	2, 2, 2, 36, 39, 3, 2, 2, 2, 37, 35, 3, 2, 2, 2, 37, 38, 3, 2, 2, 2, 38,
	42, 3, 2, 2, 2, 39, 37, 3, 2, 2, 2, 40, 42, 7, 50, 2, 2, 41, 33, 3, 2,
	2, 2, 41, 40, 3, 2, 2, 2, 42, 4, 3, 2, 2, 2, 43, 45, 9, 4, 2, 2, 44, 43,
	3, 2, 2, 2, 45, 46, 3, 2, 2, 2, 46, 44, 3, 2, 2, 2, 46, 47, 3, 2, 2, 2,
	47, 48, 3, 2, 2, 2, 48, 49, 8, 3, 2, 2, 49, 6, 3, 2, 2, 2, 50, 51, 7, 50,
	2, 2, 51, 8, 3, 2, 2, 2, 52, 56, 9, 5, 2, 2, 53, 55, 9, 6, 2, 2, 54, 53,
	3, 2, 2, 2, 55, 58, 3, 2, 2, 2, 56, 54, 3, 2, 2, 2, 56, 57, 3, 2, 2, 2,
	57, 10, 3, 2, 2, 2, 58, 56, 3, 2, 2, 2, 59, 60, 7, 47, 2, 2, 60, 61, 7,
	50, 2, 2, 61, 12, 3, 2, 2, 2, 62, 63, 7, 47, 2, 2, 63, 64, 5, 9, 5, 2,
	64, 14, 3, 2, 2, 2, 65, 66, 7, 47, 2, 2, 66, 67, 5, 3, 2, 2, 67, 68, 7,
	60, 2, 2, 68, 69, 5, 3, 2, 2, 69, 70, 7, 60, 2, 2, 70, 71, 5, 3, 2, 2,
	71, 16, 3, 2, 2, 2, 72, 73, 7, 37, 2, 2, 73, 18, 3, 2, 2, 2, 74, 75, 7,
	46, 2, 2, 75, 20, 3, 2, 2, 2, 76, 77, 7, 65, 2, 2, 77, 22, 3, 2, 2, 2,
	78, 79, 7, 45, 2, 2, 79, 24, 3, 2, 2, 2, 80, 81, 7, 44, 2, 2, 81, 26, 3,
	2, 2, 2, 82, 83, 7, 126, 2, 2, 83, 28, 3, 2, 2, 2, 84, 85, 7, 42, 2, 2,
	85, 30, 3, 2, 2, 2, 86, 87, 7, 43, 2, 2, 87, 32, 3, 2, 2, 2, 7, 2, 37,
	41, 46, 56, 3, 8, 2, 2,
}

var lexerDeserializer = antlr.NewATNDeserializer(nil)
var lexerAtn = lexerDeserializer.DeserializeFromUInt16(serializedLexerAtn)

var lexerChannelNames = []string{
	"DEFAULT_TOKEN_CHANNEL", "HIDDEN",
}

var lexerModeNames = []string{
	"DEFAULT_MODE",
}

var lexerLiteralNames = []string{
	"", "", "'0'", "", "", "", "", "'#'", "','", "'?'", "'+'", "'*'", "'|'",
	"'('", "')'",
}

var lexerSymbolicNames = []string{
	"", "WHITESPACE", "ZERO", "NUM", "WILDCARDAS", "LEGACYAS", "AS", "HASH",
	"COMMA", "QUESTIONMARK", "PLUS", "ASTERISK", "OR", "LPAR", "RPAR",
}

var lexerRuleNames = []string{
	"HEXA", "WHITESPACE", "ZERO", "NUM", "WILDCARDAS", "LEGACYAS", "AS", "HASH",
	"COMMA", "QUESTIONMARK", "PLUS", "ASTERISK", "OR", "LPAR", "RPAR",
}

type SequenceLexer struct {
	*antlr.BaseLexer
	channelNames []string
	modeNames    []string
	// TODO: EOF string
}

var lexerDecisionToDFA = make([]*antlr.DFA, len(lexerAtn.DecisionToState))

func init() {
	for index, ds := range lexerAtn.DecisionToState {
		lexerDecisionToDFA[index] = antlr.NewDFA(ds, index)
	}
}

func NewSequenceLexer(input antlr.CharStream) *SequenceLexer {

	l := new(SequenceLexer)

	l.BaseLexer = antlr.NewBaseLexer(input)
	l.Interpreter = antlr.NewLexerATNSimulator(l, lexerAtn, lexerDecisionToDFA, antlr.NewPredictionContextCache())

	l.channelNames = lexerChannelNames
	l.modeNames = lexerModeNames
	l.RuleNames = lexerRuleNames
	l.LiteralNames = lexerLiteralNames
	l.SymbolicNames = lexerSymbolicNames
	l.GrammarFileName = "Sequence.g4"
	// TODO: l.EOF = antlr.TokenEOF

	return l
}

// SequenceLexer tokens.
const (
	SequenceLexerWHITESPACE   = 1
	SequenceLexerZERO         = 2
	SequenceLexerNUM          = 3
	SequenceLexerWILDCARDAS   = 4
	SequenceLexerLEGACYAS     = 5
	SequenceLexerAS           = 6
	SequenceLexerHASH         = 7
	SequenceLexerCOMMA        = 8
	SequenceLexerQUESTIONMARK = 9
	SequenceLexerPLUS         = 10
	SequenceLexerASTERISK     = 11
	SequenceLexerOR           = 12
	SequenceLexerLPAR         = 13
	SequenceLexerRPAR         = 14
)
