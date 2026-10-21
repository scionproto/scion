// Copyright 2026 SCION Association
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

//go:build linux && (amd64 || arm64)

package afxdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"unsafe"

	"github.com/scionproto/scion/private/underlay/ebpf"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var (
	ErrRXRegionIsEmpty   = errors.New("rx region is empty")
	ErrTXRegionIsEmpty   = errors.New("tx region is empty")
	ErrCQRegionIsEmpty   = errors.New("cq region is empty")
	ErrNumFramesTooSmall = errors.New("NumFrames must be >= TxSize + RxSize")
)

// Interface owns the XDP program and eBPF maps attached to a network interface.
type Interface struct {
	ifIndex int
	iface   *net.Interface
	spec    *ciliumebpf.CollectionSpec
	coll    *ciliumebpf.Collection
	xdpLink link.Link
	// txProg is [NewTxInterface]'s standalone XDP_PASS program;
	// [NewInterface] leaves it nil.
	txProg *ciliumebpf.Program
}

// NewInterface attaches an XDP program to the named network interface.
// The program redirects packets matching address/port filters to AF_XDP sockets.
func NewInterface(ifaceName string) (*Interface, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("fetching interface by name: %w", err)
	}

	spec, err := ebpf.LoadSockfilterSpec()
	if err != nil {
		return nil, fmt.Errorf("loading sockfilter spec: %w", err)
	}

	coll, err := ciliumebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("creating eBPF collection: %w", err)
	}

	// Keep in sync with ebpf.DropReasonNames.
	if dc := coll.Maps["drop_counters"]; dc == nil {
		coll.Close()
		return nil, fmt.Errorf("no map named drop_counters found")
	} else if got, want := dc.MaxEntries(), uint32(len(ebpf.DropReasonNames)); got != want {
		coll.Close()
		return nil, fmt.Errorf(
			"drop_counters has %d entries, but ebpf.DropReasonNames has %d", got, want)
	}

	prog := coll.Programs["bpf_sock_filter"]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("no program named bpf_sock_filter found")
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attaching XDP program: %w", err)
	}

	return &Interface{
		ifIndex: iface.Index,
		iface:   iface,
		spec:    spec,
		coll:    coll,
		xdpLink: xdpLink,
	}, nil
}

// NewTxInterface prepares a netdevice for TX-only AF_XDP. It attaches XDP_PASS
// but no sockfilter, RX redirection, or drop counters. The program is required
// because drivers such as mlx5 allocate XSK queues only in XDP mode and reject
// bind with EINVAL otherwise. XDP_PASS leaves RX traffic on the normal stack.
// This supports packet generators such as the router benchmark's brload.
// Every socket opened on the returned Interface must set [SocketConfig.TxOnly].
func NewTxInterface(ifaceName string) (*Interface, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("fetching interface by name: %w", err)
	}

	// Build the XDP_PASS program in code to avoid an .o artifact.
	// It uses no helpers, so the "GPL" license string is a formality.
	prog, err := ciliumebpf.NewProgram(&ciliumebpf.ProgramSpec{
		Name:    "afxdp_txpass",
		Type:    ciliumebpf.XDP,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 2), // XDP_PASS
			asm.Return(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating XDP_PASS program: %w", err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		prog.Close()
		return nil, fmt.Errorf("attaching XDP_PASS program: %w", err)
	}

	return &Interface{
		ifIndex: iface.Index,
		iface:   iface,
		xdpLink: xdpLink,
		txProg:  prog,
	}, nil
}

// Close detaches the XDP program and releases all eBPF resources.
func (i *Interface) Close() error {
	var errs []error
	if i.xdpLink != nil {
		if err := i.xdpLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing XDP link: %w", err))
		}
		i.xdpLink = nil
	}
	if i.coll != nil {
		i.coll.Close()
		i.coll = nil
	}
	if i.txProg != nil {
		if err := i.txProg.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing XDP_PASS program: %w", err))
		}
		i.txProg = nil
	}
	return errors.Join(errs...)
}

// Name returns the underlying netdevice name (for example, "eth0")
// used as a metric label.
func (i *Interface) Name() string {
	return i.iface.Name
}

// ReadDropCounters returns the current per-reason XDP_DROP totals summed across
// all possible CPUs. Indices align with [ebpf.DropReasonNames].
func (i *Interface) ReadDropCounters() ([len(ebpf.DropReasonNames)]uint64, error) {
	var totals [len(ebpf.DropReasonNames)]uint64
	m := i.coll.Maps["drop_counters"]
	if m == nil {
		return totals, errors.New("no map named drop_counters found")
	}
	// PERCPU_ARRAY lookups return one uint64 per possible CPU.
	for reason := range len(ebpf.DropReasonNames) {
		var perCPU []uint64
		if err := m.Lookup(uint32(reason), &perCPU); err != nil {
			return totals, fmt.Errorf("reading drop_counters[%d]: %w", reason, err)
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		totals[reason] = sum
	}
	return totals, nil
}

// AddAddrPort adds an address/port filter to the sockfilter map.
// Packets matching the filter are redirected to AF_XDP sockets.
func (i *Interface) AddAddrPort(addrPort netip.AddrPort) error {
	sockMapFlt := i.coll.Maps["sock_map_flt"]
	if sockMapFlt == nil {
		return fmt.Errorf("no map named sock_map_flt found")
	}

	// Build the key matching the sockfilter addrPort structure.
	var key [20]byte
	addr := addrPort.Addr()
	if addr.Is4() || addr.Is4In6() {
		addrBytes := addr.As4()
		copy(key[0:4], addrBytes[0:4])
		key[18] = byte(4) // type = IPv4
	} else {
		addrBytes := addr.As16()
		copy(key[0:16], addrBytes[0:16])
		key[18] = byte(6) // type = IPv6
	}
	binary.BigEndian.PutUint16(key[16:18], addrPort.Port())

	b := uint8(0) // value is unused
	if err := sockMapFlt.Put(key, b); err != nil {
		return fmt.Errorf("adding address/port to sockfilter map: %w", err)
	}
	return nil
}

// InterfaceConfig controls how AF_XDP is attached to a network interface.
type InterfaceConfig struct {
	PreferHugepages bool
	PreferZerocopy  bool
}

type SocketConfig struct {
	// QueueID identifies the NIC RX/TX queue to bind to.
	QueueID uint32
	// NumFrames is the total number of UMEM frames allocated.
	NumFrames uint32
	// FrameSize defines the size of each UMEM frame in bytes.
	FrameSize uint32
	// RxSize sets the number of descriptors in the RX ring.
	RxSize uint32
	// TxSize sets the number of descriptors in the TX ring.
	TxSize uint32
	// CqSize sets the number of entries in the completion ring.
	CqSize uint32
	// BatchSize caps how many completions one [Socket.PollCompletions] call reclaims.
	// It's clamped to 256.
	BatchSize uint32
	// TxOnly disables RX and XDP redirection. A TX-only socket's fill ring is
	// registered but left empty, and RxSize is forced to 0. Requires an Interface
	// from [NewTxInterface].
	TxOnly bool
}

func (c *SocketConfig) ValidateAndSetDefaults() error {
	if c.NumFrames == 0 {
		c.NumFrames = DefaultNumFrames
	}
	if c.FrameSize == 0 {
		c.FrameSize = DefaultFrameSize
	}
	if c.TxOnly {
		// RxSize 0 gives TX the entire UMEM and reduces the minimum to
		// NumFrames >= TxSize.
		c.RxSize = 0
	} else if c.RxSize == 0 {
		c.RxSize = DefaultRxQueueSize
	}
	if c.TxSize == 0 {
		c.TxSize = DefaultTxQueueSize
	}
	if c.CqSize == 0 {
		c.CqSize = DefaultCompletionRingSize
	}
	if c.BatchSize == 0 {
		c.BatchSize = DefaultBatchSize
	}
	// Larger batches cause latency spikes in copy mode.
	if c.BatchSize > 256 {
		c.BatchSize = 256
	}
	if pageSize := uint32(os.Getpagesize()); c.FrameSize > pageSize {
		return fmt.Errorf("frame_size %d exceeds system page size (%d)",
			c.FrameSize, pageSize)
	}
	if c.NumFrames < c.TxSize+c.RxSize {
		return ErrNumFramesTooSmall
	}
	return nil
}

const (
	DefaultNumFrames          = 4096
	DefaultFrameSize          = 2048
	DefaultTxQueueSize        = 2048
	DefaultRxQueueSize        = DefaultTxQueueSize
	DefaultCompletionRingSize = 2048
	DefaultBatchSize          = 64 // Completions reclaimed per poll

	// TxMetadataLen is the TX metadata headroom [Open] reserves in front of each
	// TX frame when the kernel accepts XDP_UMEM_TX_METADATA_LEN, regardless of
	// checksum offload. It stores struct xsk_tx_metadata's flags, csum_start,
	// and csum_offset from linux/if_xdp.h plus four padding bytes, enough for
	// XDP_TXMD_FLAGS_CHECKSUM.
	TxMetadataLen = 16
)

type queuePtrs struct {
	// cachedProd caches the producer index. RX and completion rings reload *prod
	// only after cached entries run out, avoiding atomic loads. On TX it advances
	// ahead of *prod until [commitTxDescriptors] stores it.
	cachedProd uint32

	// cachedCons caches the consumer index. Userspace advances it per RX/completion
	// entry and stores it to *cons once per batch. On TX it holds *cons + size,
	// the bound for cachedProd.
	cachedCons uint32

	// mask is size-1. AF_XDP requires ring sizes to be powers of two.
	mask uint32

	// size is the number of entries in the ring.
	size uint32

	// prod points to the shared mmap producer index, updated by the kernel for
	// completion rings and by userspace for fill rings.
	prod *uint32

	// cons points to the shared mmap consumer index, advanced by userspace for
	// completion rings and by the kernel for fill rings.
	cons *uint32

	// flags points to the shared ring flags. With XDP_USE_NEED_WAKEUP, the kernel sets
	// XDP_RING_NEED_WAKEUP when it needs a kick (sendto for TX). Some zero-copy drivers
	// clear it on TX while they poll, letting the busy TX path skip sendto.
	flags *uint32
}

// xdpUQueue is an RX/TX ring of unix.XDPDesc entries into UMEM.
// It's indexed like [xdpUMemQueue], whose entries are bare uint64 UMEM addresses.
type xdpUQueue struct {
	queuePtrs
	descs []unix.XDPDesc
}

// xdpUMemQueue is a fill or completion ring of raw UMEM offsets
// shared by the kernel and userspace.
//
// See [AF_XDP rings].
//
// [AF_XDP rings]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html#rings
type xdpUMemQueue struct {
	queuePtrs
	// addrs is the power-of-two-sized ring of raw UMEM addresses.
	// Completion entries hold TX descriptor addresses past metadata headroom;
	// [Socket.PollCompletions] subtracts it to recover the frame base.
	addrs []uint64
}

func rawBind(fd int, sa *unix.RawSockaddrXDP) error {
	_, _, e := unix.Syscall(unix.SYS_BIND,
		uintptr(fd),
		uintptr(unsafe.Pointer(sa)),
		unsafe.Sizeof(*sa),
	)
	if e != 0 {
		return e
	}
	return nil
}

func setsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	_, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(name),
		uintptr(val), vallen, 0)
	if e != 0 {
		return e
	}
	return nil
}

func getsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	l := uint32(vallen) // socklen_t
	_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		uintptr(unsafe.Pointer(&l)),
		0,
	)
	if e != 0 {
		return e
	}
	return nil
}

// mmapRegion maps RX/TX/FQ/CQ rings on the AF_XDP socket.
func mmapRegion(fd int, length uintptr, offset uintptr) ([]byte, error) {
	addr, _, errno := unix.Syscall6(unix.SYS_MMAP,
		0,
		length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(fd),
		offset,
	)
	if errno != 0 {
		return nil, errno
	}
	sh := &struct {
		Addr uintptr
		Len  int
		Cap  int
	}{addr, int(length), int(length)}
	return *(*[]byte)(unsafe.Pointer(sh)), nil
}

// mmapUmem maps anonymous, page-backed UMEM.
// It prefers 2 MB huge pages for fewer TLB misses and falls back to normal pages.
func mmapUmem(
	length uintptr, preferHugepages bool,
) (buf []byte, hugepages bool, err error) {
	var addr uintptr
	var errno unix.Errno

	makeSlice := func() []byte {
		sh := &struct {
			Addr uintptr
			Len  int
			Cap  int
		}{addr, int(length), int(length)}
		return *(*[]byte)(unsafe.Pointer(sh))
	}

	if preferHugepages {
		// MAP_HUGETLB reduces TLB misses for large UMEM regions.
		addr, _, errno = unix.Syscall6(unix.SYS_MMAP,
			0,
			length,
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_HUGETLB|unix.MAP_HUGE_2MB,
			^uintptr(0), // fd = -1
			0,
		)
		if errno == 0 {
			return makeSlice(), true, nil
		}
	}

	addr, _, errno = unix.Syscall6(unix.SYS_MMAP,
		0,
		length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE,
		^uintptr(0), // fd = -1
		0,
	)
	if errno != 0 {
		return nil, hugepages, errno
	}

	return makeSlice(), hugepages, nil
}

// makeQueue builds an RX/TX descriptor queue from an mmap region and offsets.
func makeQueue(
	region []byte, off unix.XDPRingOffset, size uint32, isTx bool,
) (*xdpUQueue, error) {
	if len(region) == 0 {
		if isTx {
			return nil, ErrTXRegionIsEmpty
		}
		return nil, ErrRXRegionIsEmpty
	}
	base := unsafe.Pointer(&region[0])

	prod := (*uint32)(unsafe.Add(base, off.Producer))
	cons := (*uint32)(unsafe.Add(base, off.Consumer))
	flags := (*uint32)(unsafe.Add(base, off.Flags))

	descPtr := unsafe.Add(base, off.Desc)
	descs := unsafe.Slice((*unix.XDPDesc)(descPtr), size)

	cachedCons := uint32(0)
	if isTx {
		cachedCons = size
	}

	return &xdpUQueue{
		queuePtrs: queuePtrs{
			mask:       size - 1,
			size:       size,
			prod:       prod,
			cons:       cons,
			flags:      flags,
			cachedProd: 0,
			cachedCons: cachedCons,
		},
		descs: descs,
	}, nil
}

// makeUMemQueue builds a UMEM fill/completion queue from an mmap region and offsets.
func makeUMemQueue(
	region []byte, off unix.XDPRingOffset, size uint32,
) (*xdpUMemQueue, error) {
	if len(region) == 0 {
		return nil, ErrCQRegionIsEmpty
	}
	base := unsafe.Pointer(&region[0])

	prod := (*uint32)(unsafe.Add(base, off.Producer))
	cons := (*uint32)(unsafe.Add(base, off.Consumer))
	flags := (*uint32)(unsafe.Add(base, off.Flags))

	addrPtr := unsafe.Add(base, off.Desc)
	addrs := unsafe.Slice((*uint64)(addrPtr), size)

	return &xdpUMemQueue{
		queuePtrs: queuePtrs{
			flags:      flags,
			mask:       size - 1,
			size:       size,
			prod:       prod,
			cons:       cons,
			cachedProd: 0,
			cachedCons: 0,
		},
		addrs: addrs,
	}, nil
}

// rxAvailable returns the number of RX descriptors available to consume.
func rxAvailable(q *xdpUQueue) uint32 {
	avail := q.cachedProd - q.cachedCons
	if avail > 0 {
		return avail
	}

	q.cachedProd = atomic.LoadUint32(q.prod)
	return q.cachedProd - q.cachedCons
}

// reserveTx reserves nDescs TX descriptors starting at *idx and returns nDescs.
// It returns 0 if fewer than nDescs descriptors are free.
func reserveTx(q *xdpUQueue, nDescs uint32, idx *uint32) int {
	free := q.cachedCons - q.cachedProd
	if free < nDescs {
		cons := atomic.LoadUint32(q.cons)
		q.cachedCons = cons + q.size
		if q.cachedCons-q.cachedProd < nDescs {
			return 0
		}
	}

	*idx = q.cachedProd
	q.cachedProd += nDescs
	return int(nDescs)
}

// commitTxDescriptors publishes TX descriptors to the kernel via the producer index.
func commitTxDescriptors(queueProd *uint32, queueCachedProd uint32) {
	atomic.StoreUint32(queueProd, queueCachedProd)
}

// umemNbAvail returns the number of UMEM entries available to consume, capped by nb.
func umemNbAvail(q *xdpUMemQueue, nb uint32) uint32 {
	entries := q.cachedProd - q.cachedCons
	if entries == 0 {
		prod := atomic.LoadUint32(q.prod)
		q.cachedProd = prod
		entries = q.cachedProd - q.cachedCons
	}
	if entries > nb {
		return nb
	}
	return entries
}

// umemCompleteFromKernel copies completed UMEM addresses into
// dst and advances the consumer index.
func umemCompleteFromKernel(q *xdpUMemQueue, dst []uint64, nb uint32) uint32 {
	entries := umemNbAvail(q, nb)
	for i := range entries {
		idx := q.cachedCons & q.mask
		dst[i] = q.addrs[idx]
		q.cachedCons++
	}
	if entries > 0 {
		atomic.StoreUint32(q.cons, q.cachedCons)
	}
	return entries
}

var zeroBuf []byte

// wakeupTxQueue uses zero-length sendto to notify the kernel/NIC of new TX descriptors.
// [Open] binds with XDP_USE_NEED_WAKEUP, so the kick is needed only while
// the kernel has set XDP_RING_NEED_WAKEUP on the TX ring.
func wakeupTxQueue(fd int) error {
	err := unix.Sendto(fd, zeroBuf, unix.MSG_DONTWAIT, nil)
	if err == unix.EAGAIN || err == unix.EBUSY {
		// EAGAIN and EBUSY are non-fatal backpressure.
		return nil
	}
	return err
}

// registerXSK adds an AF_XDP socket to xsks_map for XDP redirection.
func registerXSK(iface *Interface, fd int, queueID uint32) error {
	xsksMap := iface.coll.Maps["xsks_map"]
	if xsksMap == nil {
		return fmt.Errorf("no map named xsks_map found")
	}

	if err := xsksMap.Put(queueID, uint32(fd)); err != nil {
		return fmt.Errorf("registering socket in xsks_map: %w", err)
	}
	return nil
}

// Socket is an AF_XDP bidirectional socket. It's not safe for concurrent use.
type Socket struct {
	conf          SocketConfig
	isZerocopy    bool
	isHugepages   bool
	isCsumOffload bool
	// txMetadataLen is [TxMetadataLen] if XDP_UMEM_REG accepted TX metadata,
	// otherwise 0. Its value does not depend on whether checksum offload is used.
	txMetadataLen uint32
	// txFrameLen is [SocketConfig.FrameSize] minus metadata headroom, fixed at [Open].
	txFrameLen int
	fd         int

	// umem is the contiguous region backing frames referenced by the RX/TX rings.
	umem []byte

	// tx is the TX descriptor ring. Userspace produces descriptors here;
	// the kernel/NIC consumes them to transmit packets.
	tx *xdpUQueue

	// cq is the UMEM completion ring. The kernel produces frame addresses
	// here when TX packets have been sent and their buffers can be reused.
	cq *xdpUMemQueue

	// rx is the RX descriptor ring. The kernel/NIC produces
	// descriptors here; userspace consumes them via Receive.
	rx *xdpUQueue

	// fq is the UMEM fill ring. Userspace produces frame addresses here
	// to supply fresh buffers for RX; the kernel consumes them.
	fq *xdpUMemQueue

	// txRegion and rxRegion back their ring metadata and descriptor arrays.
	txRegion, rxRegion []byte

	// cqRegion and fqRegion back the completion and fill rings.
	cqRegion, fqRegion []byte

	// freeFrames is the TX UMEM-address stack. Its length is the free count;
	// its capacity is the total TX frame count.
	freeFrames []uint64

	// compBuf is [Socket.PollCompletions]'s scratch buffer.
	compBuf []uint64
}

// TxFree returns the number of free TX descriptors in the TX ring.
func (s *Socket) TxFree() uint32 {
	// The producer may run up to size entries ahead of the kernel consumer index.
	cons := atomic.LoadUint32(s.tx.cons) + s.tx.size
	return cons - s.tx.cachedProd
}

// FreeFrames returns number of free UMEM frames available for TX.
func (s *Socket) FreeFrames() uint32 {
	return uint32(len(s.freeFrames))
}

// PrefillTx copies template into every TX UMEM frame. Generators can patch only
// mutable fields in frames returned by [Socket.NextFrame], avoiding hot-path
// full copies. The kernel leaves TX payloads unchanged, so the template survives
// completion-ring reuse. Oversized templates are truncated to [Socket.TxFrameLen].
// Call PrefillTx before any Submit.
func (s *Socket) PrefillTx(template []byte) {
	n := min(len(template), s.txFrameLen)
	// This is the same [RxSize, NumFrames) range used for s.freeFrames in Open.
	for i := s.conf.RxSize; i < s.conf.NumFrames; i++ {
		base := int(uint64(i)*uint64(s.conf.FrameSize)) + int(s.txMetadataLen)
		copy(s.umem[base:base+n], template[:n])
	}
}

// Open allocates UMEM, maps and configures rings, and binds an AF_XDP socket to
// the target NIC queue. Unless conf.TxOnly is set, it also registers the socket
// in xsks_map. iface must have an attached XDP program.
func Open(
	conf SocketConfig, iface *Interface, preferHugepages, preferZerocopy bool,
) (*Socket, error) {
	if err := conf.ValidateAndSetDefaults(); err != nil {
		return nil, err
	}

	var (
		txRegion, cqRegion, rxRegion, fqRegion, umem []byte
		fd                                           int
		err                                          error
	)

	fail := func(errf string, a ...any) error {
		if txRegion != nil {
			_ = unix.Munmap(txRegion)
		}
		if cqRegion != nil {
			_ = unix.Munmap(cqRegion)
		}
		if rxRegion != nil {
			_ = unix.Munmap(rxRegion)
		}
		if fqRegion != nil {
			_ = unix.Munmap(fqRegion)
		}
		if umem != nil {
			_ = unix.Munmap(umem)
		}
		if fd != 0 {
			_ = unix.Close(fd)
		}
		return fmt.Errorf(errf, a...)
	}

	fd, err = unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fail("opening AF_XDP socket: %w", err)
	}

	// Allocate UMEM, preferring huge pages if requested.
	umemLen := uintptr(conf.NumFrames) * uintptr(conf.FrameSize)
	var hugepages bool
	umem, hugepages, err = mmapUmem(umemLen, preferHugepages)
	if err != nil {
		return nil, fail("mmap UMEM: %w", err)
	}

	// Request TX metadata for checksum offload; retry without it if unsupported.
	var hasTxMetadata bool
	reg := unix.XDPUmemReg{
		Addr:            uint64(uintptr(unsafe.Pointer(&umem[0]))),
		Len:             uint64(len(umem)),
		Size:            conf.FrameSize,
		Headroom:        0,
		Flags:           unix.XDP_UMEM_TX_METADATA_LEN,
		Tx_metadata_len: TxMetadataLen,
	}
	err = setsockopt(
		fd, unix.SOL_XDP, unix.XDP_UMEM_REG,
		unsafe.Pointer(&reg), unsafe.Sizeof(reg),
	)
	if err != nil {
		// Retry without TX metadata.
		reg.Flags = 0
		reg.Tx_metadata_len = 0
		if err := setsockopt(
			fd, unix.SOL_XDP, unix.XDP_UMEM_REG,
			unsafe.Pointer(&reg), unsafe.Sizeof(reg),
		); err != nil {
			return nil, fail("setsockopt XDP_UMEM_REG: %w", err)
		}
	} else {
		hasTxMetadata = true
	}

	// The kernel requires UMEM owners to register fill and completion rings
	// before bind, even for TX-only sockets (otherwise EINVAL).
	// With RxSize 0, TX-only sockets register an empty CqSize fill ring.
	fillSize := conf.RxSize
	if conf.TxOnly {
		fillSize = conf.CqSize
	}
	compSize := conf.CqSize
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING,
		unsafe.Pointer(&fillSize), unsafe.Sizeof(fillSize),
	); err != nil {
		return nil, fail("setsockopt XDP_UMEM_FILL_RING: %w", err)
	}
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING,
		unsafe.Pointer(&compSize), unsafe.Sizeof(compSize),
	); err != nil {
		return nil, fail("setsockopt XDP_UMEM_COMPLETION_RING: %w", err)
	}

	txSize := conf.TxSize
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_TX_RING,
		unsafe.Pointer(&txSize), unsafe.Sizeof(txSize),
	); err != nil {
		return nil, fail("setsockopt XDP_TX_RING: %w", err)
	}

	if !conf.TxOnly {
		rxSize := conf.RxSize
		if err := setsockopt(
			fd, unix.SOL_XDP, unix.XDP_RX_RING,
			unsafe.Pointer(&rxSize), unsafe.Sizeof(rxSize),
		); err != nil {
			return nil, fail("setsockopt XDP_RX_RING: %w", err)
		}
	}

	var offs unix.XDPMmapOffsets
	if err := getsockopt(
		fd, unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		unsafe.Pointer(&offs), unsafe.Sizeof(offs),
	); err != nil {
		return nil, fail("getsockopt XDP_MMAP_OFFSETS: %w", err)
	}

	txRegionLen := uintptr(offs.Tx.Desc) +
		uintptr(conf.TxSize)*unsafe.Sizeof(unix.XDPDesc{})
	txRegion, err = mmapRegion(fd, txRegionLen, unix.XDP_PGOFF_TX_RING)
	if err != nil {
		return nil, fail("mmap TX ring: %w", err)
	}

	cqRegionLen := uintptr(offs.Cr.Desc) + uintptr(conf.CqSize)*unsafe.Sizeof(uint64(0))
	cqRegion, err = mmapRegion(fd, cqRegionLen, unix.XDP_UMEM_PGOFF_COMPLETION_RING)
	if err != nil {
		return nil, fail("mmap CQ ring: %w", err)
	}

	txQ, err := makeQueue(txRegion, offs.Tx, conf.TxSize, true)
	if err != nil {
		return nil, fail("making TX queue: %w", err)
	}
	cqQ, err := makeUMemQueue(cqRegion, offs.Cr, conf.CqSize)
	if err != nil {
		return nil, fail("making CQ queue: %w", err)
	}

	// TX-only sockets leave rxQ nil and rxRegion unmapped.
	var rxQ *xdpUQueue
	if !conf.TxOnly {
		rxRegionLen := uintptr(offs.Rx.Desc) +
			uintptr(conf.RxSize)*unsafe.Sizeof(unix.XDPDesc{})
		rxRegion, err = mmapRegion(fd, rxRegionLen, unix.XDP_PGOFF_RX_RING)
		if err != nil {
			return nil, fail("mmap RX ring: %w", err)
		}
		rxQ, err = makeQueue(rxRegion, offs.Rx, conf.RxSize, false)
		if err != nil {
			return nil, fail("making RX queue: %w", err)
		}
	}

	// Every UMEM owner needs a fill ring. TX-only sockets leave it empty, keeping
	// all frames available to the TX freelist.
	fqRegionLen := uintptr(offs.Fr.Desc) + uintptr(fillSize)*unsafe.Sizeof(uint64(0))
	fqRegion, err = mmapRegion(fd, fqRegionLen, unix.XDP_UMEM_PGOFF_FILL_RING)
	if err != nil {
		return nil, fail("mmap FQ ring: %w", err)
	}
	fqQ, err := makeUMemQueue(fqRegion, offs.Fr, fillSize)
	if err != nil {
		return nil, fail("making FQ queue: %w", err)
	}

	if !conf.TxOnly {
		// Populate FQ with initial UMEM frames for RX.
		prod := atomic.LoadUint32(fqQ.prod)
		for i := range fqQ.size {
			idx := (prod + i) & fqQ.mask
			fqQ.addrs[idx] = uint64(i) * uint64(conf.FrameSize)
		}

		atomic.StoreUint32(fqQ.prod, prod+fqQ.size)
		fqQ.cachedProd = atomic.LoadUint32(fqQ.prod)
		fqQ.cachedCons = atomic.LoadUint32(fqQ.cons)
	}

	sa := &unix.RawSockaddrXDP{
		Family:   unix.AF_XDP,
		Ifindex:  uint32(iface.ifIndex),
		Queue_id: conf.QueueID,
	}

	// XDP_USE_NEED_WAKEUP lets [Socket.FlushTx] skip sendto while the TX flag is clear.
	zerocopy := preferZerocopy
	if zerocopy {
		sa.Flags = unix.XDP_ZEROCOPY | unix.XDP_USE_NEED_WAKEUP
	} else {
		sa.Flags = unix.XDP_COPY | unix.XDP_USE_NEED_WAKEUP
	}

	err = rawBind(fd, sa)
	if err != nil && zerocopy {
		// Unsupported zero-copy returns EPROTONOSUPPORT or EOPNOTSUPP; veth returns
		// EOPNOTSUPP because it lacks ndo_xsk_wakeup.
		if errno, ok := err.(unix.Errno); ok &&
			(errno == unix.EPROTONOSUPPORT || errno == unix.EOPNOTSUPP) {
			sa.Flags = unix.XDP_COPY | unix.XDP_USE_NEED_WAKEUP
			zerocopy = false
			err = rawBind(fd, sa)
		}
	}
	if err != nil {
		return nil, fail("binding socket: %w", err)
	}

	// TX-only sockets receive no redirected packets.
	// An Interface from [NewTxInterface] has no xsks_map either.
	if !conf.TxOnly {
		if err := registerXSK(iface, fd, conf.QueueID); err != nil {
			return nil, fail("registering XSK: %w", err)
		}
	}

	// The TX freelist contains frames [RxSize, NumFrames).
	freeFrames := make([]uint64, conf.NumFrames-conf.RxSize)
	for i := range freeFrames {
		frameIdx := conf.RxSize + uint32(i)
		freeFrames[i] = uint64(frameIdx) * uint64(conf.FrameSize)
	}

	// txMdLen must match XDP_UMEM_REG even without offload because TX descriptor
	// addresses must point past the metadata.
	var txMdLen uint32
	if hasTxMetadata {
		txMdLen = TxMetadataLen
	}

	// Enable offload only if metadata was accepted, the device advertises AF_XDP
	// tx-checksum, and this queue uses zero-copy.
	var deviceTxChecksum bool
	if hasTxMetadata {
		deviceTxChecksum, err = queryTxChecksumOffload(iface.ifIndex)
		if err != nil {
			// If support cannot be verified, disable offload rather than risk sending
			// partial checksums that the NIC does not complete.
			deviceTxChecksum = false
		}
	}
	csumOffload := hasTxMetadata && zerocopy && deviceTxChecksum

	return &Socket{
		conf:          conf,
		isZerocopy:    zerocopy,
		isHugepages:   hugepages,
		isCsumOffload: csumOffload,
		txMetadataLen: txMdLen,
		txFrameLen:    int(conf.FrameSize) - int(txMdLen),
		fd:            fd,
		umem:          umem,
		tx:            txQ,
		cq:            cqQ,
		rx:            rxQ,
		fq:            fqQ,
		txRegion:      txRegion,
		rxRegion:      rxRegion,
		cqRegion:      cqRegion,
		fqRegion:      fqRegion,
		freeFrames:    freeFrames,
		compBuf:       make([]uint64, conf.BatchSize),
	}, nil
}

// IsZerocopy reports whether the socket uses zero-copy. When preferZerocopy is true,
// [Open] falls back to XDP_COPY if the queue lacks XDP_ZEROCOPY.
func (s *Socket) IsZerocopy() bool { return s.isZerocopy }

// IsHugepages reports whether the socket UMEM was mmapped via hugepages.
func (s *Socket) IsHugepages() bool { return s.isHugepages }

// IsCsumOffload reports XDP_TXMD_FLAGS_CHECKSUM support.
// When true, use [Socket.SubmitCsumOffload] for hardware checksum computation.
func (s *Socket) IsCsumOffload() bool { return s.isCsumOffload }

// QueueID returns the NIC RX/TX queue this socket is bound to.
func (s *Socket) QueueID() uint32 { return s.conf.QueueID }

// SocketStats mirrors the kernel's struct xdp_statistics.
// All counters are monotonic totals since socket creation.
//
// See the XDP_STATISTICS section of the AF_XDP [docs].
//
// [docs]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html#xdp-statistics-getsockopt
type SocketStats struct {
	RxDropped            uint64 // Drops for other reasons, e.g. an empty fill ring in copy mode.
	RxInvalidDescs       uint64 // RX descriptors with invalid address/length.
	TxInvalidDescs       uint64 // TX descriptors with invalid address/length.
	RxRingFull           uint64 // Packets dropped because RX ring was full.
	RxFillRingEmptyDescs uint64 // Times the kernel found the fill ring empty.
	TxRingEmptyDescs     uint64 // Times the kernel found the TX ring empty.
}

// Stats reads the kernel's AF_XDP socket statistics via
// getsockopt(SOL_XDP, XDP_STATISTICS).
func (s *Socket) Stats() (SocketStats, error) {
	var raw unix.XDPStatistics
	if err := getsockopt(s.fd, unix.SOL_XDP, unix.XDP_STATISTICS,
		unsafe.Pointer(&raw), unsafe.Sizeof(raw)); err != nil {
		return SocketStats{}, fmt.Errorf("getsockopt(XDP_STATISTICS): %w", err)
	}
	return SocketStats{
		RxDropped:            raw.Rx_dropped,
		RxInvalidDescs:       raw.Rx_invalid_descs,
		TxInvalidDescs:       raw.Tx_invalid_descs,
		RxRingFull:           raw.Rx_ring_full,
		RxFillRingEmptyDescs: raw.Rx_fill_ring_empty_descs,
		TxRingEmptyDescs:     raw.Tx_ring_empty_descs,
	}, nil
}

// Close releases the socket, UMEM and kernel resources.
func (s *Socket) Close() error {
	var errs []error

	if s.fd != 0 {
		if err := unix.Close(s.fd); err != nil {
			errs = append(errs, fmt.Errorf("closing fd: %w", err))
		}
		s.fd = 0
	}

	// Explicitly unmap UMEM and ring regions.
	if s.txRegion != nil {
		if err := unix.Munmap(s.txRegion); err != nil {
			errs = append(errs, fmt.Errorf("munmap TX ring: %w", err))
		}
		s.txRegion = nil
	}
	if s.rxRegion != nil {
		if err := unix.Munmap(s.rxRegion); err != nil {
			errs = append(errs, fmt.Errorf("munmap RX ring: %w", err))
		}
		s.rxRegion = nil
	}
	if s.cqRegion != nil {
		if err := unix.Munmap(s.cqRegion); err != nil {
			errs = append(errs, fmt.Errorf("munmap CQ ring: %w", err))
		}
		s.cqRegion = nil
	}
	if s.fqRegion != nil {
		if err := unix.Munmap(s.fqRegion); err != nil {
			errs = append(errs, fmt.Errorf("munmap FQ ring: %w", err))
		}
		s.fqRegion = nil
	}
	if s.umem != nil {
		if err := unix.Munmap(s.umem); err != nil {
			errs = append(errs, fmt.Errorf("munmap UMEM: %w", err))
		}
		s.umem = nil
	}

	return errors.Join(errs...)
}

// Wait blocks until the socket is readable or the timeout expires,
// returning an error only for system call failures.
func (s *Socket) Wait(timeoutMS int) error {
	for {
		_, err := unix.Poll([]unix.PollFd{{
			Fd:     int32(s.fd),
			Events: unix.POLLIN,
		}}, timeoutMS)

		if err == nil {
			return nil
		}

		// Signals interrupt poll with EINTR, e.g. the Go runtime's SIGURG preemption,
		// profilers and SIGCHLD.
		if err == unix.EINTR {
			continue
		}

		return err
	}
}

// Receive retrieves up to len(buffer) frames from the RX ring.
// Returned frames reference UMEM and must be returned via Release.
func (s *Socket) Receive(buffer []Frame) []Frame {
	avail := rxAvailable(s.rx)
	if avail == 0 {
		return nil
	}

	if max := uint32(len(buffer)); avail > max {
		avail = max
	}
	buffer = buffer[:avail]

	for i := range avail {
		idx := s.rx.cachedCons & s.rx.mask
		d := s.rx.descs[idx]

		start := int(d.Addr)
		end := start + int(d.Len)

		buffer[i].Buf = s.umem[start:end]
		buffer[i].Addr = d.Addr

		s.rx.cachedCons++
	}

	atomic.StoreUint32(s.rx.cons, s.rx.cachedCons)
	return buffer
}

// Release returns a received frame to the fill queue for reuse.
func (s *Socket) Release(frame Frame) {
	// Each released frame came from the fill ring,
	// which has one slot per RX frame and cannot overflow.
	prod := atomic.LoadUint32(s.fq.prod)
	idx := prod & s.fq.mask

	s.fq.addrs[idx] = frame.Addr
	atomic.StoreUint32(s.fq.prod, prod+1)
}

// ReleaseBatch returns a batch of received frames to the fill queue for reuse.
func (s *Socket) ReleaseBatch(frames []Frame) {
	prod := atomic.LoadUint32(s.fq.prod)
	for _, fr := range frames {
		idx := prod & s.fq.mask
		s.fq.addrs[idx] = fr.Addr
		prod++
	}
	atomic.StoreUint32(s.fq.prod, prod)
}

// Frame represents a borrowed UMEM frame from an AF_XDP socket.
type Frame struct {
	// Buf points directly into UMEM and can be modified without an extra copy.
	Buf []byte

	// Addr is the frame's UMEM address. Return a frame from [Socket.NextFrame] by
	// passing Addr to a Submit method or [Socket.ReleaseTxFrame], and a frame from
	// [Socket.Receive] with [Socket.Release] or [Socket.ReleaseBatch].
	Addr uint64
}

// NextFrame returns a writable UMEM buffer and address.
// A zero value means none is available; retry after [Socket.PollCompletions].
//
// If the kernel accepted TX metadata headroom, Buf starts after it regardless of
// [Socket.IsCsumOffload]. [Socket.SubmitCsumOffload] writes that metadata.
func (s *Socket) NextFrame() Frame {
	if len(s.freeFrames) == 0 {
		s.PollCompletions(uint32(len(s.compBuf)))
		if len(s.freeFrames) == 0 {
			return Frame{}
		}
	}

	n := len(s.freeFrames) - 1
	addr := s.freeFrames[n]
	s.freeFrames = s.freeFrames[:n]

	start := int(addr) + int(s.txMetadataLen)

	return Frame{
		Buf:  s.umem[start : start+s.txFrameLen],
		Addr: addr,
	}
}

// ReleaseTxFrame returns an unsubmitted [Socket.NextFrame] frame to the TX freelist.
// Call it for every frame not passed to [Socket.Submit], [Socket.SubmitCsumOffload],
// or [Socket.SubmitBatch]; only submitted frames produce completions,
// so unreleased frames remain unavailable for the socket's lifetime.
// addr is the unadjusted [Frame.Addr].
func (s *Socket) ReleaseTxFrame(addr uint64) {
	s.freeFrames = append(s.freeFrames, addr)
}

// TxFrameLen returns the length of the [Frame.Buf] returned by [Socket.NextFrame].
// Use it to discard oversized packets before borrowing a frame.
func (s *Socket) TxFrameLen() int {
	return s.txFrameLen
}

// Submit writes a TX descriptor, visible to the kernel after [Socket.FlushTx].
// Reserved metadata headroom is skipped in the descriptor address.
func (s *Socket) Submit(addr uint64, length uint32) error {
	var idx uint32

	for reserveTx(s.tx, 1, &idx) <= 0 {
		if s.PollCompletions(s.conf.BatchSize) == 0 {
			if err := wakeupTxQueue(s.fd); err != nil {
				return err
			}
		}
	}

	d := &s.tx.descs[idx&s.tx.mask]
	d.Addr = addr + uint64(s.txMetadataLen)
	d.Len = length
	d.Options = 0
	return nil
}

// SubmitCsumOffload writes xsk_tx_metadata before the packet and sets the descriptor's
// XDP_TX_METADATA option. The kernel sees the descriptor after [Socket.FlushTx].
//
// csumStart is the packet-relative checksum start, usually the UDP header;
// csumOffset locates the checksum field from there (6 for UDP).
func (s *Socket) SubmitCsumOffload(
	addr uint64, length uint32, csumStart, csumOffset uint16,
) error {
	var idx uint32

	for reserveTx(s.tx, 1, &idx) <= 0 {
		if s.PollCompletions(s.conf.BatchSize) == 0 {
			if err := wakeupTxQueue(s.fd); err != nil {
				return err
			}
		}
	}

	// xsk_tx_metadata: flags(8) + csum_start(2) + csum_offset(2) + pad(4).
	mdStart := int(addr)
	binary.LittleEndian.PutUint64(s.umem[mdStart:], unix.XDP_TXMD_FLAGS_CHECKSUM)
	binary.LittleEndian.PutUint16(s.umem[mdStart+8:], csumStart)
	binary.LittleEndian.PutUint16(s.umem[mdStart+10:], csumOffset)
	// bytes 12-15 are padding, leave as-is.

	d := &s.tx.descs[idx&s.tx.mask]
	d.Addr = addr + uint64(s.txMetadataLen) // Packet data starts after metadata.
	d.Len = length
	d.Options = unix.XDP_TX_METADATA
	return nil
}

// SubmitBatch writes TX descriptors for a batch of frames;
// the kernel sees them only after [Socket.FlushTx].
func (s *Socket) SubmitBatch(addrs []uint64, lens []uint32) (int, error) {
	n := len(addrs)
	if n == 0 {
		return 0, nil
	}

	var idx uint32
retry:
	if reserveTx(s.tx, uint32(n), &idx) == 0 {
		if s.PollCompletions(s.conf.BatchSize) == 0 {
			if err := wakeupTxQueue(s.fd); err != nil {
				return 0, err
			}
		}
		goto retry
	}

	base := idx & s.tx.mask
	mdOff := uint64(s.txMetadataLen)
	for i := range n {
		d := &s.tx.descs[(base+uint32(i))&s.tx.mask]
		d.Addr = addrs[i] + mdOff
		d.Len = lens[i]
		d.Options = 0
	}

	return n, nil
}

// FlushTx publishes submitted descriptors and kicks the TX queue if the kernel
// set XDP_RING_NEED_WAKEUP. Call it after submitting.
func (s *Socket) FlushTx() error {
	commitTxDescriptors(s.tx.prod, s.tx.cachedProd)
	// A clear NEED_WAKEUP means the driver is draining TX, so skip sendto.
	// Only some zero-copy drivers clear it. In copy mode, every flush calls sendto.
	if atomic.LoadUint32(s.tx.flags)&unix.XDP_RING_NEED_WAKEUP == 0 {
		return nil
	}
	return wakeupTxQueue(s.fd)
}

// PollCompletions moves up to maxFrames completed TX frames from the completion
// ring to the freelist and returns the moved count.
// maxFrames is capped at [SocketConfig.BatchSize].
func (s *Socket) PollCompletions(maxFrames uint32) uint32 {
	if maxFrames == 0 {
		return 0
	}
	maxFrames = min(maxFrames, uint32(len(s.compBuf)))

	n := umemCompleteFromKernel(s.cq, s.compBuf, maxFrames)
	mdOff := uint64(s.txMetadataLen)
	for i := range n {
		// Completion addresses include txMetadataLen; subtract it for the frame base.
		s.freeFrames = append(s.freeFrames, s.compBuf[i]-mdOff)
	}
	return n
}
