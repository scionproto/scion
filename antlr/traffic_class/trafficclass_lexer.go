// File generated by ANTLR. DO NOT EDIT.

package traffic_class

import (
	"fmt"
	"unicode"

	"github.com/antlr/antlr4/runtime/Go/antlr"
)

// Suppress unused import error
var _ = fmt.Printf
var _ = unicode.IsLetter

var serializedLexerAtn = []uint16{
	3, 24715, 42794, 33075, 47597, 16764, 15335, 30598, 22884, 2, 22, 171,
	8, 1, 4, 2, 9, 2, 4, 3, 9, 3, 4, 4, 9, 4, 4, 5, 9, 5, 4, 6, 9, 6, 4, 7,
	9, 7, 4, 8, 9, 8, 4, 9, 9, 9, 4, 10, 9, 10, 4, 11, 9, 11, 4, 12, 9, 12,
	4, 13, 9, 13, 4, 14, 9, 14, 4, 15, 9, 15, 4, 16, 9, 16, 4, 17, 9, 17, 4,
	18, 9, 18, 4, 19, 9, 19, 4, 20, 9, 20, 4, 21, 9, 21, 3, 2, 3, 2, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 5, 3, 5, 3, 6, 3, 6,
	3, 7, 3, 7, 3, 8, 3, 8, 3, 8, 3, 8, 3, 8, 3, 9, 3, 9, 3, 9, 3, 9, 3, 9,
	3, 9, 3, 10, 6, 10, 73, 10, 10, 13, 10, 14, 10, 74, 3, 10, 3, 10, 3, 11,
	3, 11, 3, 11, 7, 11, 82, 10, 11, 12, 11, 14, 11, 85, 11, 11, 5, 11, 87,
	10, 11, 3, 12, 6, 12, 90, 10, 12, 13, 12, 14, 12, 91, 3, 13, 3, 13, 3,
	13, 3, 13, 3, 13, 3, 13, 3, 13, 3, 13, 3, 13, 3, 13, 3, 14, 3, 14, 3, 14,
	3, 14, 3, 14, 3, 14, 5, 14, 110, 10, 14, 3, 15, 3, 15, 3, 15, 3, 15, 3,
	15, 3, 15, 5, 15, 118, 10, 15, 3, 16, 3, 16, 3, 16, 3, 16, 3, 16, 3, 16,
	5, 16, 126, 10, 16, 3, 17, 3, 17, 3, 17, 3, 17, 3, 17, 3, 17, 3, 17, 3,
	17, 5, 17, 136, 10, 17, 3, 18, 3, 18, 3, 18, 3, 18, 3, 18, 3, 18, 5, 18,
	144, 10, 18, 3, 19, 3, 19, 3, 19, 3, 19, 3, 19, 3, 19, 5, 19, 152, 10,
	19, 3, 20, 3, 20, 3, 20, 3, 20, 3, 20, 3, 20, 3, 20, 3, 20, 5, 20, 162,
	10, 20, 3, 21, 3, 21, 3, 21, 3, 21, 3, 21, 3, 21, 5, 21, 170, 10, 21, 2,
	2, 22, 3, 3, 5, 4, 7, 5, 9, 6, 11, 7, 13, 8, 15, 9, 17, 10, 19, 11, 21,
	12, 23, 13, 25, 14, 27, 15, 29, 16, 31, 17, 33, 18, 35, 19, 37, 20, 39,
	21, 41, 22, 3, 2, 6, 5, 2, 11, 12, 15, 15, 34, 34, 3, 2, 51, 59, 3, 2,
	50, 59, 5, 2, 50, 59, 67, 72, 99, 104, 2, 182, 2, 3, 3, 2, 2, 2, 2, 5,
	3, 2, 2, 2, 2, 7, 3, 2, 2, 2, 2, 9, 3, 2, 2, 2, 2, 11, 3, 2, 2, 2, 2, 13,
	3, 2, 2, 2, 2, 15, 3, 2, 2, 2, 2, 17, 3, 2, 2, 2, 2, 19, 3, 2, 2, 2, 2,
	21, 3, 2, 2, 2, 2, 23, 3, 2, 2, 2, 2, 25, 3, 2, 2, 2, 2, 27, 3, 2, 2, 2,
	2, 29, 3, 2, 2, 2, 2, 31, 3, 2, 2, 2, 2, 33, 3, 2, 2, 2, 2, 35, 3, 2, 2,
	2, 2, 37, 3, 2, 2, 2, 2, 39, 3, 2, 2, 2, 2, 41, 3, 2, 2, 2, 3, 43, 3, 2,
	2, 2, 5, 45, 3, 2, 2, 2, 7, 49, 3, 2, 2, 2, 9, 54, 3, 2, 2, 2, 11, 56,
	3, 2, 2, 2, 13, 58, 3, 2, 2, 2, 15, 60, 3, 2, 2, 2, 17, 65, 3, 2, 2, 2,
	19, 72, 3, 2, 2, 2, 21, 86, 3, 2, 2, 2, 23, 89, 3, 2, 2, 2, 25, 93, 3,
	2, 2, 2, 27, 109, 3, 2, 2, 2, 29, 117, 3, 2, 2, 2, 31, 125, 3, 2, 2, 2,
	33, 135, 3, 2, 2, 2, 35, 143, 3, 2, 2, 2, 37, 151, 3, 2, 2, 2, 39, 161,
	3, 2, 2, 2, 41, 169, 3, 2, 2, 2, 43, 44, 7, 63, 2, 2, 44, 4, 3, 2, 2, 2,
	45, 46, 7, 63, 2, 2, 46, 47, 7, 50, 2, 2, 47, 48, 7, 122, 2, 2, 48, 6,
	3, 2, 2, 2, 49, 50, 7, 101, 2, 2, 50, 51, 7, 110, 2, 2, 51, 52, 7, 117,
	2, 2, 52, 53, 7, 63, 2, 2, 53, 8, 3, 2, 2, 2, 54, 55, 7, 42, 2, 2, 55,
	10, 3, 2, 2, 2, 56, 57, 7, 46, 2, 2, 57, 12, 3, 2, 2, 2, 58, 59, 7, 43,
	2, 2, 59, 14, 3, 2, 2, 2, 60, 61, 7, 118, 2, 2, 61, 62, 7, 116, 2, 2, 62,
	63, 7, 119, 2, 2, 63, 64, 7, 103, 2, 2, 64, 16, 3, 2, 2, 2, 65, 66, 7,
	104, 2, 2, 66, 67, 7, 99, 2, 2, 67, 68, 7, 110, 2, 2, 68, 69, 7, 117, 2,
	2, 69, 70, 7, 103, 2, 2, 70, 18, 3, 2, 2, 2, 71, 73, 9, 2, 2, 2, 72, 71,
	3, 2, 2, 2, 73, 74, 3, 2, 2, 2, 74, 72, 3, 2, 2, 2, 74, 75, 3, 2, 2, 2,
	75, 76, 3, 2, 2, 2, 76, 77, 8, 10, 2, 2, 77, 20, 3, 2, 2, 2, 78, 87, 7,
	50, 2, 2, 79, 83, 9, 3, 2, 2, 80, 82, 9, 4, 2, 2, 81, 80, 3, 2, 2, 2, 82,
	85, 3, 2, 2, 2, 83, 81, 3, 2, 2, 2, 83, 84, 3, 2, 2, 2, 84, 87, 3, 2, 2,
	2, 85, 83, 3, 2, 2, 2, 86, 78, 3, 2, 2, 2, 86, 79, 3, 2, 2, 2, 87, 22,
	3, 2, 2, 2, 88, 90, 9, 5, 2, 2, 89, 88, 3, 2, 2, 2, 90, 91, 3, 2, 2, 2,
	91, 89, 3, 2, 2, 2, 91, 92, 3, 2, 2, 2, 92, 24, 3, 2, 2, 2, 93, 94, 5,
	21, 11, 2, 94, 95, 7, 48, 2, 2, 95, 96, 5, 21, 11, 2, 96, 97, 7, 48, 2,
	2, 97, 98, 5, 21, 11, 2, 98, 99, 7, 48, 2, 2, 99, 100, 5, 21, 11, 2, 100,
	101, 7, 49, 2, 2, 101, 102, 5, 21, 11, 2, 102, 26, 3, 2, 2, 2, 103, 104,
	7, 67, 2, 2, 104, 105, 7, 80, 2, 2, 105, 110, 7, 91, 2, 2, 106, 107, 7,
	99, 2, 2, 107, 108, 7, 112, 2, 2, 108, 110, 7, 123, 2, 2, 109, 103, 3,
	2, 2, 2, 109, 106, 3, 2, 2, 2, 110, 28, 3, 2, 2, 2, 111, 112, 7, 67, 2,
	2, 112, 113, 7, 78, 2, 2, 113, 118, 7, 78, 2, 2, 114, 115, 7, 99, 2, 2,
	115, 116, 7, 110, 2, 2, 116, 118, 7, 110, 2, 2, 117, 111, 3, 2, 2, 2, 117,
	114, 3, 2, 2, 2, 118, 30, 3, 2, 2, 2, 119, 120, 7, 80, 2, 2, 120, 121,
	7, 81, 2, 2, 121, 126, 7, 86, 2, 2, 122, 123, 7, 112, 2, 2, 123, 124, 7,
	113, 2, 2, 124, 126, 7, 118, 2, 2, 125, 119, 3, 2, 2, 2, 125, 122, 3, 2,
	2, 2, 126, 32, 3, 2, 2, 2, 127, 128, 7, 68, 2, 2, 128, 129, 7, 81, 2, 2,
	129, 130, 7, 81, 2, 2, 130, 136, 7, 78, 2, 2, 131, 132, 7, 100, 2, 2, 132,
	133, 7, 113, 2, 2, 133, 134, 7, 113, 2, 2, 134, 136, 7, 110, 2, 2, 135,
	127, 3, 2, 2, 2, 135, 131, 3, 2, 2, 2, 136, 34, 3, 2, 2, 2, 137, 138, 7,
	85, 2, 2, 138, 139, 7, 84, 2, 2, 139, 144, 7, 69, 2, 2, 140, 141, 7, 117,
	2, 2, 141, 142, 7, 116, 2, 2, 142, 144, 7, 101, 2, 2, 143, 137, 3, 2, 2,
	2, 143, 140, 3, 2, 2, 2, 144, 36, 3, 2, 2, 2, 145, 146, 7, 70, 2, 2, 146,
	147, 7, 85, 2, 2, 147, 152, 7, 86, 2, 2, 148, 149, 7, 102, 2, 2, 149, 150,
	7, 117, 2, 2, 150, 152, 7, 118, 2, 2, 151, 145, 3, 2, 2, 2, 151, 148, 3,
	2, 2, 2, 152, 38, 3, 2, 2, 2, 153, 154, 7, 70, 2, 2, 154, 155, 7, 85, 2,
	2, 155, 156, 7, 69, 2, 2, 156, 162, 7, 82, 2, 2, 157, 158, 7, 102, 2, 2,
	158, 159, 7, 117, 2, 2, 159, 160, 7, 101, 2, 2, 160, 162, 7, 114, 2, 2,
	161, 153, 3, 2, 2, 2, 161, 157, 3, 2, 2, 2, 162, 40, 3, 2, 2, 2, 163, 164,
	7, 86, 2, 2, 164, 165, 7, 81, 2, 2, 165, 170, 7, 85, 2, 2, 166, 167, 7,
	118, 2, 2, 167, 168, 7, 113, 2, 2, 168, 170, 7, 117, 2, 2, 169, 163, 3,
	2, 2, 2, 169, 166, 3, 2, 2, 2, 170, 42, 3, 2, 2, 2, 16, 2, 74, 83, 86,
	89, 91, 109, 117, 125, 135, 143, 151, 161, 169, 3, 8, 2, 2,
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
	"", "'='", "'=0x'", "'cls='", "'('", "','", "')'", "'true'", "'false'",
}

var lexerSymbolicNames = []string{
	"", "", "", "", "", "", "", "", "", "WHITESPACE", "DIGITS", "HEX_DIGITS",
	"NET", "ANY", "ALL", "NOT", "BOOL", "SRC", "DST", "DSCP", "TOS",
}

var lexerRuleNames = []string{
	"T__0", "T__1", "T__2", "T__3", "T__4", "T__5", "T__6", "T__7", "WHITESPACE",
	"DIGITS", "HEX_DIGITS", "NET", "ANY", "ALL", "NOT", "BOOL", "SRC", "DST",
	"DSCP", "TOS",
}

type TrafficClassLexer struct {
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

func NewTrafficClassLexer(input antlr.CharStream) *TrafficClassLexer {

	l := new(TrafficClassLexer)

	l.BaseLexer = antlr.NewBaseLexer(input)
	l.Interpreter = antlr.NewLexerATNSimulator(l, lexerAtn, lexerDecisionToDFA, antlr.NewPredictionContextCache())

	l.channelNames = lexerChannelNames
	l.modeNames = lexerModeNames
	l.RuleNames = lexerRuleNames
	l.LiteralNames = lexerLiteralNames
	l.SymbolicNames = lexerSymbolicNames
	l.GrammarFileName = "TrafficClass.g4"
	// TODO: l.EOF = antlr.TokenEOF

	return l
}

// TrafficClassLexer tokens.
const (
	TrafficClassLexerT__0       = 1
	TrafficClassLexerT__1       = 2
	TrafficClassLexerT__2       = 3
	TrafficClassLexerT__3       = 4
	TrafficClassLexerT__4       = 5
	TrafficClassLexerT__5       = 6
	TrafficClassLexerT__6       = 7
	TrafficClassLexerT__7       = 8
	TrafficClassLexerWHITESPACE = 9
	TrafficClassLexerDIGITS     = 10
	TrafficClassLexerHEX_DIGITS = 11
	TrafficClassLexerNET        = 12
	TrafficClassLexerANY        = 13
	TrafficClassLexerALL        = 14
	TrafficClassLexerNOT        = 15
	TrafficClassLexerBOOL       = 16
	TrafficClassLexerSRC        = 17
	TrafficClassLexerDST        = 18
	TrafficClassLexerDSCP       = 19
	TrafficClassLexerTOS        = 20
)
