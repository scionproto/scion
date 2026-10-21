// Package afxdp provides zero-copy-capable AF_XDP sockets.
// Interface owns the XDP program and eBPF objects; Socket binds to one RX/TX queue.
//
// AF_XDP uses four rings:
//
//   - RX: raw packets delivered from the NIC to userspace.
//   - FQ: UMEM addresses supplied by userspace for RX.
//   - TX: descriptors sent from userspace to the NIC.
//   - CQ: completed TX buffers returned by the kernel.
package afxdp
