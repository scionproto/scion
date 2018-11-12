package main

import (
	"fmt"

	"github.com/kormat/fmt15"

	"github.com/scionproto/scion/go/border/braccept/tpkt"
)

// BRTest defines a single test
type BRTest struct {
	Desc string
	// In is the packet being sent to the border router
	In tpkt.Packer
	// Out is the list of expected packets. No expected packets means that the packet
	// should be dropped by the border router, and nothing is expected.
	Out []tpkt.Matcher
}

func (t *BRTest) Summary(testPass bool) string {
	var result string
	if testPass {
		result = pass()
	} else {
		result = fail()
	}
	return fmt.Sprintf("Test %s: %s\n%s", t.Desc, result, t.In)
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
