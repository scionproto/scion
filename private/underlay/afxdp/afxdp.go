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

//go:build linux

// Package afxdp implements AF_XDP zero-copy capable sockets.
// Interface owns XDP program + eBPF objects.
// Socket is an AF_XDP socket bound to a specific RX/TX queue.
//
// Terminology mapping (kernel ↔ userspace):
//
//   - RX ring: raw packets delivered from NIC to userspace.
//   - FQ ring: UMEM addresses userspace provides to kernel for RX.
//   - TX ring: descriptors userspace sends to NIC.
//   - CQ ring: completed TX buffers returned by kernel.
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
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var (
	ErrTXRegionIsEmpty   = errors.New("tx region is empty")
	ErrCQRegionIsEmpty   = errors.New("cq region is empty")
	ErrNumFramesTooSmall = errors.New("NumFrames must be >= TxSize + RxSize")
)

// Interface represents a network interface with an attached XDP program.
// It manages the eBPF program and maps for AF_XDP socket redirection.
type Interface struct {
	ifIndex int
	iface   *net.Interface
	spec    *ciliumebpf.CollectionSpec
	coll    *ciliumebpf.Collection
	xdpLink link.Link
}

// NewInterface creates and attaches an XDP program to the specified network interface.
// The XDP program redirects packets matching address/port filters to AF_XDP sockets.
func NewInterface(ifaceName string) (*Interface, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("fetching interface by name: %w", err)
	}

	// Load the sockfilter eBPF program spec and create a collection.
	spec, err := ebpf.LoadSockfilterSpec()
	if err != nil {
		return nil, fmt.Errorf("loading sockfilter spec: %w", err)
	}

	coll, err := ciliumebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("creating eBPF collection: %w", err)
	}

	// Get the XDP program from the collection.
	prog := coll.Programs["bpf_sock_filter"]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("no program named bpf_sock_filter found")
	}

	// Attach the XDP program to the network interface.
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
	return errors.Join(errs...)
}

// AddAddrPort adds an address/port pair to the sockfilter map.
// Packets destined to this address/port will be redirected to AF_XDP sockets.
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
	// BatchSize controls TX and completion processing batch size.
	// Very large values do not help and can hurt copy-mode performance,
	// so we clamp them in ValidateAndSetDefaults.
	BatchSize uint32
}

func (c *SocketConfig) ValidateAndSetDefaults() error {
	if c.NumFrames == 0 {
		c.NumFrames = DefaultNumFrames
	}
	if c.FrameSize == 0 {
		c.FrameSize = DefaultFrameSize
	}
	if c.RxSize == 0 {
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
	// Hard upper bound: larger batches cause latency spikes and bad behavior
	// in copy-mode; AF_XDP works best with modest batches.
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
	DefaultBatchSize          = 64 // TX batching
)

/*---- Queue wrappers ----*/

type queuePtrs struct {
	// cachedProd is the userspace-local copy of the producer index.
	// We batch-load the real producer index from *prod to reduce
	// cacheline and atomic operations when checking for available entries.
	cachedProd uint32

	// cachedCons is the userspace-local copy of the consumer index.
	// We advance this locally while consuming entries and flush it
	// back to *cons only after a batch, for the same reasons as with cachedProd.
	cachedCons uint32

	// mask is size-1 and is used for cheap wrapping of ring indices
	// (idx & mask) instead of a modulo operation. Assumes size is a
	// power of two, as required by AF_XDP.
	mask uint32

	// size is the total number of entries in the ring.
	// It defines the valid index range and the maximum number of
	// in-flight UMEM addresses the ring can hold.
	size uint32

	// prod points into the shared ring header producer index in the
	// mmap'ed region. For completion rings, this is updated by the
	// kernel; for fill rings, it is updated by userspace.
	prod *uint32

	// cons points into the shared ring header consumer index in the
	// mmap'ed region. For completion rings, this is advanced by
	// userspace as entries are reclaimed; for fill rings, by the kernel.
	cons *uint32
}

// xdpUQueue is conceptually identical to xdpUMemQueue in terms of indexing.
// The key difference is the payload.
//   - xdpUQueue: descriptors pointing into UMEM (unix.XDPDesc),
//   - xdpUMemQueue: bare UMEM frame addresses (uint64) for FILL/COMPLETION.
type xdpUQueue struct {
	queuePtrs
	descs []unix.XDPDesc
}

// xdpUMemQueue represents a UMEM address ring (FILL or COMPLETION).
// Entries are raw UMEM offsets managed by kernel and userspace.
//
// See https://www.kernel.org/doc/html/latest/networking/af_xdp.html#rings.
type xdpUMemQueue struct {
	queuePtrs
	// addrs is the ring itself: a power-of-two-sized slice of UMEM
	// offsets. Each element is the base address of a frame inside the
	// UMEM area, as seen by both kernel and userspace.
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

// mmapUmem maps an anonymous, page-backed region for UMEM.
// First attempts to use hugepages (2MB) for better TLB performance,
// falls back to normal pages if hugepages are unavailable.
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
		// Try hugepages first (MAP_HUGETLB with 2MB pages)
		// This reduces TLB misses significantly for large UMEM regions.
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
		// Hugepages allocation failed, fall back to normal pages.
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

// makeQueue builds RX/TX user queue from mmap + offsets.
func makeQueue(
	region []byte, off unix.XDPRingOffset, size uint32, isTx bool,
) (*xdpUQueue, error) {
	if len(region) == 0 {
		return nil, ErrTXRegionIsEmpty
	}
	base := unsafe.Pointer(&region[0])

	prod := (*uint32)(unsafe.Add(base, off.Producer))
	cons := (*uint32)(unsafe.Add(base, off.Consumer))

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
			cachedProd: 0,
			cachedCons: cachedCons,
		},
		descs: descs,
	}, nil
}

// makeUMemQueue builds UMEM completion queue from mmap + offsets.
func makeUMemQueue(
	region []byte, off unix.XDPRingOffset, size uint32,
) (*xdpUMemQueue, error) {
	if len(region) == 0 {
		return nil, ErrCQRegionIsEmpty
	}
	base := unsafe.Pointer(&region[0])

	prod := (*uint32)(unsafe.Add(base, off.Producer))
	cons := (*uint32)(unsafe.Add(base, off.Consumer))

	addrPtr := unsafe.Add(base, off.Desc)
	addrs := unsafe.Slice((*uint64)(addrPtr), size)

	return &xdpUMemQueue{
		queuePtrs: queuePtrs{
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

/*---- Queue operations ----*/

// rxAvailable returns the number of RX descriptors available to consume.
func rxAvailable(q *xdpUQueue) uint32 {
	avail := q.cachedProd - q.cachedCons
	if avail > 0 {
		return avail
	}

	q.cachedProd = atomic.LoadUint32(q.prod)
	return q.cachedProd - q.cachedCons
}

// reserveTx reserves nDescs TX descriptors if space is available.
// Returns zero if the ring is full.
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

// commitTxDescriptors publishes TX descriptors to the kernel
// by updating the producer index.
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

// umemCompleteFromKernel copies completed UMEM addresses into dst
// and advances the consumer index.
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

// wakeupTxQueue notifies the kernel/NIC that new TX descriptors are ready.
// AF_XDP interprets a zero-length sendto() as a doorbell signal to process
// the TX ring. This is required when XDP_USE_NEED_WAKEUP is enabled.
func wakeupTxQueue(fd int) error {
	// zero-length wakeup; AF_XDP treats this as a "kick"
	err := unix.Sendto(fd, zeroBuf, unix.MSG_DONTWAIT, nil)
	if err == unix.EAGAIN || err == unix.EBUSY {
		// Treat EAGAIN (and optionally EBUSY) as non-fatal backpressure.
		return nil
	}
	return err
}

// registerXSK registers an AF_XDP socket file descriptor in the xsks_map.
// This allows the XDP program to redirect packets to the socket.
func registerXSK(iface *Interface, fd int, queueID uint32) error {
	xsksMap := iface.coll.Maps["xsks_map"]
	if xsksMap == nil {
		return fmt.Errorf("no map named xsks_map found")
	}

	// The key is the queue ID, the value is the socket FD.
	if err := xsksMap.Put(queueID, uint32(fd)); err != nil {
		return fmt.Errorf("registering socket in xsks_map: %w", err)
	}
	return nil
}

// Socket is an AF_XDP bidirectional socket.
//
// WARNING: Socket is not safe for concurrent use.
type Socket struct {
	conf        SocketConfig
	isZerocopy  bool
	isHugepages bool
	fd          int

	// umem is the contiguous UMEM region backing all RX/TX frames.
	// Both RX and TX rings reference offsets into this slice.
	umem []byte

	// tx is the TX descriptor ring. Userspace produces
	// descriptors here; the kernel/NIC consumes them to transmit packets.
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

	// txRegion is the mmaped memory backing the TX ring metadata and descriptor array.
	// rxRegion is the mmaped memory backing the RX ring metadata and descriptor array.
	txRegion, rxRegion []byte

	// cqRegion and fqRegion are the mmaped memory regions backing the
	// COMPLETION and FILL rings respectively.
	cqRegion, fqRegion []byte

	// freeFrames is the freelist (stack) of UMEM frame addresses dedicated to TX.
	// len(freeFrames) is the number of currently-free frames; cap(freeFrames)
	// is the total TX frame pool capacity.
	freeFrames []uint64

	// compBuf is a scratch buffer used when draining the completion ring
	// in PollCompletions().
	compBuf []uint64
}

// TxFree returns the number of free TX descriptors in the TX ring.
func (s *Socket) TxFree() uint32 {
	// cons = kernel consumer index
	cons := atomic.LoadUint32(s.tx.cons) + s.tx.size
	return cons - s.tx.cachedProd
}

// FreeFrames returns number of free UMEM frames available for TX.
func (s *Socket) FreeFrames() uint32 {
	return uint32(len(s.freeFrames))
}

// Open creates and initializes an AF_XDP socket. It allocates UMEM, maps rings,
// configures kernel structures, binds to the target NIC queue and registers the
// socket in xsks_map. The iface parameter must be a properly initialized
// Interface with the XDP program attached.
func Open(
	conf SocketConfig, iface *Interface, preferHugepages, preferZerocopy bool,
) (*Socket, error) {
	// Apply defaults if necessary.
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

	// AF_XDP socket.
	fd, err = unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fail("opening AF_XDP socket: %w", err)
	}

	// UMEM registration with hugepages support.
	umemLen := uintptr(conf.NumFrames) * uintptr(conf.FrameSize)
	var hugepages bool
	umem, hugepages, err = mmapUmem(umemLen, preferHugepages)
	if err != nil {
		return nil, fail("mmap UMEM: %w", err)
	}

	reg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(&umem[0]))),
		Len:      uint64(len(umem)),
		Size:     conf.FrameSize,
		Headroom: 0,
	}
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_UMEM_REG,
		unsafe.Pointer(&reg), unsafe.Sizeof(reg),
	); err != nil {
		return nil, fail("setsockopt XDP_UMEM_REG: %w", err)
	}

	// UMEM ring sizes.
	fillSize := conf.RxSize
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

	// TX ring size on socket.
	txSize := conf.TxSize
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_TX_RING,
		unsafe.Pointer(&txSize), unsafe.Sizeof(txSize),
	); err != nil {
		return nil, fail("setsockopt XDP_TX_RING: %w", err)
	}

	// RX ring size on socket.
	rxSize := conf.RxSize
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_RX_RING,
		unsafe.Pointer(&rxSize), unsafe.Sizeof(rxSize),
	); err != nil {
		return nil, fail("setsockopt XDP_RX_RING: %w", err)
	}

	// Query mmap offsets for all rings.
	var offs unix.XDPMmapOffsets
	if err := getsockopt(
		fd, unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		unsafe.Pointer(&offs), unsafe.Sizeof(offs),
	); err != nil {
		return nil, fail("setsockopt XDP_MMAP_OFFSETS: %w", err)
	}

	// Map TX ring (descriptors).
	txRegionLen := uintptr(offs.Tx.Desc) + uintptr(conf.TxSize)*unsafe.Sizeof(unix.XDPDesc{})
	txRegion, err = mmapRegion(fd, txRegionLen, unix.XDP_PGOFF_TX_RING)
	if err != nil {
		return nil, fail("mmap TX ring: %w", err)
	}

	// Map CQ ring (UMEM completion ring, uint64 addresses).
	cqRegionLen := uintptr(offs.Cr.Desc) + uintptr(conf.CqSize)*unsafe.Sizeof(uint64(0))
	cqRegion, err = mmapRegion(fd, cqRegionLen, unix.XDP_UMEM_PGOFF_COMPLETION_RING)
	if err != nil {
		return nil, fail("mmap CQ ring: %w", err)
	}

	// Map RX ring
	rxRegionLen := uintptr(offs.Rx.Desc) + uintptr(conf.RxSize)*unsafe.Sizeof(unix.XDPDesc{})
	rxRegion, err = mmapRegion(fd, rxRegionLen, unix.XDP_PGOFF_RX_RING)
	if err != nil {
		return nil, fail("mmap RX ring: %w", err)
	}

	// Map FQ ring (UMEM fill ring, uint64 addresses)
	fqRegionLen := uintptr(offs.Fr.Desc) + uintptr(conf.RxSize)*unsafe.Sizeof(uint64(0))
	fqRegion, err = mmapRegion(fd, fqRegionLen, unix.XDP_UMEM_PGOFF_FILL_RING)
	if err != nil {
		return nil, fail("mmap FQ ring: %w", err)
	}

	// Build queues.
	txQ, err := makeQueue(txRegion, offs.Tx, conf.TxSize, true)
	if err != nil {
		return nil, fail("making TX queue: %w", err)
	}
	cqQ, err := makeUMemQueue(cqRegion, offs.Cr, conf.CqSize)
	if err != nil {
		return nil, fail("making CQ queue: %w", err)
	}
	rxQ, err := makeQueue(rxRegion, offs.Rx, conf.RxSize, false)
	if err != nil {
		return nil, fail("making RX queue: %w", err)
	}
	fqQ, err := makeUMemQueue(fqRegion, offs.Fr, conf.RxSize)
	if err != nil {
		return nil, fail("making FQ queue: %w", err)
	}

	{ // Populate FQ with initial UMEM frames.
		prod := atomic.LoadUint32(fqQ.prod)
		for i := range fqQ.size {
			idx := (prod + i) & fqQ.mask
			fqQ.addrs[idx] = uint64(i) * uint64(conf.FrameSize)
		}

		atomic.StoreUint32(fqQ.prod, prod+fqQ.size)
		fqQ.cachedProd = atomic.LoadUint32(fqQ.prod)
		fqQ.cachedCons = atomic.LoadUint32(fqQ.cons)
	}

	// Bind AF_XDP socket to iface:queue.
	sa := &unix.RawSockaddrXDP{
		Family:   unix.AF_XDP,
		Ifindex:  uint32(iface.ifIndex),
		Queue_id: conf.QueueID,
	}

	zerocopy := preferZerocopy
	if zerocopy {
		sa.Flags = unix.XDP_ZEROCOPY
	} else {
		sa.Flags = unix.XDP_COPY
	}

	err = rawBind(fd, sa)
	if err != nil && zerocopy {
		// If zerocopy is not supported for this device/queue, fall back to copy mode.
		// The kernel returns EPROTONOSUPPORT or EOPNOTSUPP depending on where the
		// check fails (e.g. veth lacks ndo_xsk_wakeup → EOPNOTSUPP).
		if errno, ok := err.(unix.Errno); ok &&
			(errno == unix.EPROTONOSUPPORT || errno == unix.EOPNOTSUPP) {
			sa.Flags = unix.XDP_COPY
			zerocopy = false
			err = rawBind(fd, sa)
		}
	}
	if err != nil {
		return nil, fail("binding socket: %w", err)
	}

	// Register the socket FD in the xsks_map so the XDP program can redirect packets to it.
	if err := registerXSK(iface, fd, conf.QueueID); err != nil {
		return nil, fail("registering XSK: %w", err)
	}

	// Local free-frame pool for TX only: frames [RxSize .. NumFrames-1].
	freeFrames := make([]uint64, conf.NumFrames-conf.RxSize)
	for i := range freeFrames {
		frameIdx := conf.RxSize + uint32(i)
		freeFrames[i] = uint64(frameIdx) * uint64(conf.FrameSize)
	}

	return &Socket{
		conf:        conf,
		isZerocopy:  zerocopy,
		isHugepages: hugepages,
		fd:          fd,
		umem:        umem,
		tx:          txQ,
		cq:          cqQ,
		rx:          rxQ,
		fq:          fqQ,
		txRegion:    txRegion,
		rxRegion:    rxRegion,
		cqRegion:    cqRegion,
		fqRegion:    fqRegion,
		freeFrames:  freeFrames,
		compBuf:     make([]uint64, conf.BatchSize),
	}, nil
}

// IsZerocopy reports whether the socket is operating in zero-copy mode.
// May return false even if PreferZerocopy was true because the corresponding queue
// may not support XDP_ZEROCOPY mode and the socket fall back to XDP_COPY automatically.
func (s *Socket) IsZerocopy() bool { return s.isZerocopy }

// IsHugepages reports whether the socket UMEM was mmapped via hugepages.
func (s *Socket) IsHugepages() bool { return s.isHugepages }

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
			errs = append(errs, err)
		}
		s.txRegion = nil
	}
	if s.rxRegion != nil {
		if err := unix.Munmap(s.rxRegion); err != nil {
			errs = append(errs, err)
		}
		s.rxRegion = nil
	}

	if s.cqRegion != nil {
		if err := unix.Munmap(s.cqRegion); err != nil {
			errs = append(errs, err)
		}
		s.cqRegion = nil
	}
	if s.fqRegion != nil {
		if err := unix.Munmap(s.fqRegion); err != nil {
			errs = append(errs, err)
		}
		s.fqRegion = nil
	}

	if s.umem != nil {
		if err := unix.Munmap(s.umem); err != nil {
			errs = append(errs, err)
		}
		s.umem = nil
	}

	return errors.Join(errs...)
}

// Wait blocks until the AF_XDP socket becomes readable or the timeout expires.
// Returns nil when the socket becomes readable OR when the timeout expires.
// Returns a non-nil error only for real system call failures.
func (s *Socket) Wait(timeoutMS int) error {
	for {
		_, err := unix.Poll([]unix.PollFd{{
			Fd:     int32(s.fd),
			Events: unix.POLLIN,
		}}, timeoutMS)

		if err == nil {
			return nil
		}

		// EINTR is not treated as an error and will never be surfaced to the caller.
		// This ensures stable behavior in environments where signals are delivered
		// (profilers, debuggers, timers, SIGCHLD, etc.).
		if err == unix.EINTR {
			continue // Retry on signal interruption.
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
	// Single producer: for every packet we receive, we return one buffer.
	// This keeps FQ occupancy bounded without fancy accounting.
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
	// Buf points directly into the UMEM region and can be written to
	// without additional copying.
	Buf []byte

	// Addr is the UMEM address that must be passed
	// back to Submit() after the frame has been filled.
	Addr uint64
}

// NextFrame returns a writable UMEM buffer and its address.
// A zero-value frame indicates that no frame is currently available and the
// caller should retry after PollCompletions().
func (s *Socket) NextFrame() Frame {
	if len(s.freeFrames) == 0 {
		// Try to reclaim some completions.
		s.PollCompletions(uint32(len(s.compBuf)))
		if len(s.freeFrames) == 0 {
			return Frame{}
		}
	}

	n := len(s.freeFrames) - 1
	addr := s.freeFrames[n]
	s.freeFrames = s.freeFrames[:n]

	frameSize := s.conf.FrameSize
	if frameSize == 0 {
		frameSize = DefaultFrameSize
	}

	start := int(addr)
	end := start + int(frameSize)

	return Frame{
		Buf:  s.umem[start:end],
		Addr: addr,
	}
}

// Submit publishes the frame to the TX ring.
func (s *Socket) Submit(addr uint64, length uint32) error {
	var idx uint32

	// Reserve one descriptor; spin until we get space.
	for reserveTx(s.tx, 1, &idx) <= 0 {
		// Ring full: try to reclaim and wake up the NIC.
		if s.PollCompletions(s.conf.BatchSize) == 0 {
			if err := wakeupTxQueue(s.fd); err != nil {
				return err
			}
		}
	}

	d := &s.tx.descs[idx&s.tx.mask]
	d.Addr = addr
	d.Len = length
	d.Options = 0
	return nil
}

// SubmitBatch publishes a batch of frames to the TX ring.
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
	for i := range n {
		d := &s.tx.descs[(base+uint32(i))&s.tx.mask]
		d.Addr = addrs[i]
		d.Len = lens[i]
		d.Options = 0
	}

	return n, nil
}

// FlushTx notifies the kernel/NIC that TX descriptors are available.
// Required when XDP_USE_NEED_WAKEUP is enabled.
func (s *Socket) FlushTx() error {
	// Commit all pending descriptors and ring the doorbell.
	commitTxDescriptors(s.tx.prod, s.tx.cachedProd)
	return wakeupTxQueue(s.fd)
}

// PollCompletions reclaims completed frames from the kernel.
// maxFrames specifies the maximum number of completed frames the caller wishes
// to reclaim in this call. The actual number processed may be lower if
// fewer completions are available. The value is also capped internally
// by the size of the completion buffer.
func (s *Socket) PollCompletions(maxFrames uint32) uint32 {
	if maxFrames == 0 {
		return 0
	}
	maxFrames = min(maxFrames, uint32(len(s.compBuf)))

	n := umemCompleteFromKernel(s.cq, s.compBuf, maxFrames)
	for i := range n {
		// cap(freeFrames) was pre-allocated to the total TX pool size,
		// so this will not allocate as long as we don't exceed that.
		s.freeFrames = append(s.freeFrames, s.compBuf[i])
	}
	return n
}
