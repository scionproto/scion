package main

import (
	"fmt"
	"strings"

	"github.com/kormat/fmt15"

	"github.com/scionproto/scion/go/border/braccept/pkti"
)

// BRTest defines a single test
type BRTest struct {
	Desc string
	// In is the packet being sent to the border router
	In pkti.PktGen
	// Out is the list of expected packets. No expected packets means that the packet
	// should be dropped by the border router, and nothing is expected.
	Out []pkti.PktMatch
}

func (t *BRTest) Summary(testPass bool) string {
	var result string
	if testPass {
		result = pass()
	} else {
		result = fail()
	}
	var str []string
	str = append(str, fmt.Sprintf("Test %s: %s", t.Desc, result))
	pi := t.In.GetPktInfo()
	if a := pi.AddrHdr; a != nil {
		str = append(str, fmt.Sprintf("\t%s,[%s] -> %s,[%s]",
			a.SrcIA, a.SrcHost, a.DstIA, a.DstHost))
	}
	if pi.Path != nil {
		str = append(str, pkti.PrintSegments(pi.Path.Segs, "\t", "\n"))
	}
	return strings.Join(str, "\n")
}

const (
	//	defColorFmt = "\x1b[%dm%s\x1b[0m"
	passUni = "\u2714"
	failUni = "\u2715"
	green   = 32
	red     = 31
)

func pass() string {
	//	return fmt.Sprintf(defColorFmt, green, passUni)
	return fmt15.ColorStr(passUni, green)
}

func fail() string {
	//	return fmt.Sprintf(defColorFmt, red, failUni)
	return fmt15.ColorStr(failUni, red)
}
