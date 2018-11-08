package pkti

var _ PktGen = (*PktMerge)(nil)
var _ PktMatch = (*PktMerge)(nil)

// PktMerge merges the common header specified in the test with an auto generated common header
// and also takes any other fields (AddrHdr, Path, etc.) from a base packet.
// The aceptance framework will merge the expected packets with the packet being sent, such as the
// expected packet only specifies the information that varies with respect to the packet sent.
type PktMerge struct {
	PktInfo
}

func (p *PktMerge) Setup() {
	p.mergeCmnHdr()
}
