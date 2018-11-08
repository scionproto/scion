package pkti

var _ PktGen = (*PktGenCmn)(nil)
var _ PktMatch = (*PktGenCmn)(nil)

// PktGenCmn merges the common header specified in the test with an auto generated common header.
type PktGenCmn struct {
	PktInfo
}

// Generate common header from packet info and replace the values provided by the user.
func (p *PktGenCmn) Merge(_ *PktInfo) {
	p.mergeCmnHdr()
}

func (p *PktGenCmn) Setup() {
	p.mergeCmnHdr()
}
