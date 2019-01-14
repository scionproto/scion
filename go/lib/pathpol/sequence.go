// Copyright 2019 ETH Zurich, Anapaya Systems
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

// This is a parser for path sequences.
// Please, don't delete the commented Printfs. They are useful when debugging the parser.

package pathpol

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/antlr/antlr4/runtime/Go/antlr"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathpol/sequence"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

const (
	isdWildcard = "([0-9]+)"
	asWildcard  = "(([0-9]+)|([0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+))"
	ifWildcard  = "([0-9]+)"
)

type Sequence struct {
	re     *regexp.Regexp
	srcstr string
	restr  string
}

// NewSequence creates a new sequence from a string
func NewSequence(s string) (*Sequence, error) {
	//fmt.Printf("COMPILE: %s\n", s)
	if s == "" {
		return &Sequence{}, nil
	}
	istream := antlr.NewInputStream(s)
	lexer := sequence.NewSequenceLexer(istream)
	lexer.RemoveErrorListeners()
	errListener := &errorListener{}
	lexer.AddErrorListener(errListener)
	tstream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)
	parser := sequence.NewSequenceParser(tstream)
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errListener)
	listener := sequenceListener{}
	antlr.ParseTreeWalkerDefault.Walk(&listener, parser.Start())
	if errListener.msg != "" {
		return nil, common.NewBasicError("Failed to parse a sequence", nil,
			"sequence", s, "msg", errListener.msg)
	}
	restr := fmt.Sprintf("^%s$", listener.stack[0])
	re, err := regexp.Compile(restr)
	if err != nil {
		// This should never happen. Sequence parser should produce a valid regexp.
		return nil, common.NewBasicError("Error while parsing sequence regexp", err,
			"regexp", restr)
	}
	return &Sequence{re: re, srcstr: s, restr: restr}, nil
}

// Eval evaluates the interface sequence list and returns the set of paths that match the list
func (s *Sequence) Eval(inputSet spathmeta.AppPathSet) spathmeta.AppPathSet {
	if s == nil || s.srcstr == "" {
		return inputSet
	}
	resultSet := make(spathmeta.AppPathSet)
	for key, path := range inputSet {
		ifaces := path.Entry.Path.Interfaces
		// Path should contain even number of interfaces. 1 for source AS,
		// 1 for destination AS and 2 per each intermediate AS. Invalid paths should
		// not occur but if they do let's ignore them.
		if len(ifaces) == 0 || len(ifaces)%2 != 0 {
			log.Error("Invalid path with even number of hops", "path", path)
			continue
		}
		// Turn the path into a string. For each AS on the path there will be
		// one element in form <IA>#<inbound-interface>,<outbound-interface>,
		// e.g. 64-ff00:0:112#3,5. For the source AS, the inbound interface will be
		// zero. For destination AS, outbound interface will be zero.
		p := fmt.Sprintf("%s#0,%d ", ifaces[0].ISD_AS(), ifaces[0].IfID)
		for i := 1; i < len(ifaces)-1; i += 2 {
			p += fmt.Sprintf("%s#%d,%d ", ifaces[i].ISD_AS(),
				ifaces[i].IfID, ifaces[i+1].IfID)
		}
		p += fmt.Sprintf("%s#%d,0 ", ifaces[len(ifaces)-1].ISD_AS(),
			ifaces[len(ifaces)-1].IfID)
		// Check whether the string matches the sequence regexp.
		//fmt.Printf("EVAL: %s\n", p)
		if s.re.MatchString(p) {
			resultSet[key] = path
		}
	}
	return resultSet
}

func (s *Sequence) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.srcstr)
}

func (s *Sequence) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}
	sn, err := NewSequence(str)
	if err != nil {
		return err
	}
	*s = *sn
	return nil
}

type errorListener struct {
	*antlr.DefaultErrorListener
	msg string
}

func (l *errorListener) SyntaxError(recognizer antlr.Recognizer, offendingSymbol interface{}, line,
	column int, msg string, e antlr.RecognitionException) {

	//fmt.Printf("Error: %s\n", msg)
	l.msg += fmt.Sprintf("%d:%d %s\n", line, column, msg)
}

type sequenceListener struct {
	*sequence.BaseSequenceListener
	stack []string
}

func (l *sequenceListener) push(s string) {
	l.stack = append(l.stack, s)
}

func (l *sequenceListener) pop() string {
	var result string
	if len(l.stack) == 0 {
		// X is used as a substitute for the token during recovery from parsing errors.
		result = "X"
	} else {
		result = l.stack[len(l.stack)-1]
		l.stack = l.stack[:len(l.stack)-1]
	}
	return result
}

func (l *sequenceListener) ExitStart(c *sequence.StartContext) {
	re := l.pop()
	//fmt.Printf("Start: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitQuestionMark(c *sequence.QuestionMarkContext) {
	re := fmt.Sprintf("(%s)?", l.pop())
	//fmt.Printf("QuestionMark: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitPlus(c *sequence.PlusContext) {
	re := fmt.Sprintf("(%s)+", l.pop())
	//fmt.Printf("Plus: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitAsterisk(c *sequence.AsteriskContext) {
	re := fmt.Sprintf("(%s)*", l.pop())
	//fmt.Printf("Asterisk: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitOr(c *sequence.OrContext) {
	right, left := l.pop(), l.pop()
	re := fmt.Sprintf("(%s|%s)", left, right)
	//fmt.Printf("Or: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitConcatenation(c *sequence.ConcatenationContext) {
	right, left := l.pop(), l.pop()
	re := fmt.Sprintf("(%s%s)", left, right)
	//fmt.Printf("Concatenation: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitParentheses(c *sequence.ParenthesesContext) {
	re := l.pop()
	//fmt.Printf("Parentheses: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitHop(c *sequence.HopContext) {
	re := fmt.Sprintf("(%s +)", l.pop())
	//fmt.Printf("Hop: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitISDHop(c *sequence.ISDHopContext) {
	isd := l.pop()
	re := fmt.Sprintf("(%s-%s#%s,%s)", isd, asWildcard, ifWildcard, ifWildcard)
	//fmt.Printf("ISDHop: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitISDASHop(c *sequence.ISDASHopContext) {
	as, isd := l.pop(), l.pop()
	re := fmt.Sprintf("(%s-%s#%s,%s)", isd, as, ifWildcard, ifWildcard)
	//fmt.Printf("ISDASHop: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitISDASIFHop(c *sequence.ISDASIFHopContext) {
	iface, as, isd := l.pop(), l.pop(), l.pop()
	re := fmt.Sprintf("(%s-%s#((%s,%s)|(%s,%s)))",
		isd, as, ifWildcard, iface, iface, ifWildcard)
	//fmt.Printf("ISDASIFHop: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitISDASIFIFHop(c *sequence.ISDASIFIFHopContext) {
	ifout, ifin, as, isd := l.pop(), l.pop(), l.pop(), l.pop()
	re := fmt.Sprintf("(%s-%s#%s,%s)", isd, as, ifin, ifout)
	//fmt.Printf("ISDASIFIFHop: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitWildcardISD(c *sequence.WildcardISDContext) {
	re := isdWildcard
	//fmt.Printf("WildcardISD: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitISD(c *sequence.ISDContext) {
	re := c.GetText()
	//fmt.Printf("ISD: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitWildcardAS(c *sequence.WildcardASContext) {
	re := asWildcard
	//fmt.Printf("WildcardAS: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitLegacyAS(c *sequence.LegacyASContext) {
	re := c.GetText()[1:]
	//fmt.Printf("LegacyAS: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitAS(c *sequence.ASContext) {
	re := c.GetText()[1:]
	//fmt.Printf("AS: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitWildcardIFace(c *sequence.WildcardIFaceContext) {
	re := ifWildcard
	//fmt.Printf("WildcardIFace: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}

func (l *sequenceListener) ExitIFace(c *sequence.IFaceContext) {
	re := c.GetText()
	//fmt.Printf("IFace: %s RE: %s\n", c.GetText(), re)
	l.push(re)
}
