package pkti

var _ PktGen = (*PktRaw)(nil)
var _ PktMatch = (*PktRaw)(nil)

// PktRaw does not do any type of merging, it just uses the specified packet info from the test.
type PktRaw struct {
	PktInfo
}

func (p *PktRaw) Merge(pi *PktInfo) {
	// Do nothing
}

func (p *PktRaw) Setup() {
	// Do nothing
}
