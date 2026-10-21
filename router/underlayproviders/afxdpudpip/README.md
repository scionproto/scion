# afxdpudpip — AF_XDP UDP/IP Underlay

This SCION router underlay carries SCION packets wrapped in Ethernet/IP/UDP over raw AF_XDP
sockets. It uses `XDP_ZEROCOPY` where supported and otherwise falls back to copy mode. On
zerocopy queues, it also enables IPv6 UDP checksum offload when the kernel and driver
advertise AF_XDP `tx-checksum`.

The underlay is opt-in. Set `router.preferred_underlays.udpip` to `"afxdp"`. The default is
`inet`. See [doc/manuals/router.rst](../../../doc/manuals/router.rst).

## Scope and Limitations

This underlay targets the common SCION use case, with these constraints:

- **No IP fragmentation.** On TX, IPv4 sets DF per
  [RFC 791 §3.1](https://www.rfc-editor.org/rfc/rfc791#section-3.1), and IPv6 emits no Fragment
  extension header per [RFC 8200 §4.5](https://www.rfc-editor.org/rfc/rfc8200#section-4.5). On
  RX, only the first IPv4 fragment contains the UDP header, so only it reliably matches an
  AF_XDP filter. XDP drops a matching first fragment (`MF=1`); later fragments have a nonzero
  offset, usually pass to the kernel, and are discarded when reassembly times out. IPv6
  fragments take the non-UDP branch because `NextHeader=44`; the kernel receives and discards
  them because no socket is bound to the relevant ports. Thus, no fragments reach the SCION
  router's userspace RX path. The path MTU comes from SCION path metadata, so a fragment
  indicates a misconfigured peer or non-conforming sender.
- **MTU is limited by the configured UMEM `frame_size`.** The default supports Ethernet MTU
  1500; jumbo frames are unsupported. See *AF_XDP Per-Link Options* in
  [doc/manuals/router.rst](../../../doc/manuals/router.rst) for tuning options.

For other L2 transports for IP/UDP, use the `inet` udpip underlay.

## Packet Lifecycle

### RX Path

```mermaid
flowchart TD
    subgraph NIC
        A[NIC receives Ethernet frame — DMA to ring buffer]
    end

    subgraph eBPF ["eBPF (kernel, runs per packet)"]
        B[Parse Ethernet + IP + UDP when present]
        BF{IPv4 fragment?}
        C{Dest IP:port in sock_map_flt?}
        D[XDP_PASS — kernel stack]
        E[bpf_redirect_map → AF_XDP socket by queue ID]
        F[XDP_PASS — ARP / ICMPv6 to kernel]
        G[XDP_DROP — malformed]
        GF[XDP_DROP — fragment of filtered flow]
    end

    subgraph Userspace ["Userspace (Go)"]
        H[socket.Wait + socket.Receive — up to 64 frames]
        I[Copy each frame to packet buffer — release UMEM frame]
        J{Parse Ethertype per frame}
        K[IPv4: extract 4-byte IPs — require protocol 17]
        L[IPv6: extract 16-byte IPs — require protocol 17]
        M{Lookup link by address}
        N[PTP link: known remote peer]
        O[Internal: store remote address in HeadBytes]
        P[Drop as invalid]
        Q[receivePacket: FNV-1a hash of flow ID + address header]
        R[Enqueue to processor queue]
    end

    A --> B
    B --> C
    C -->|yes| BF
    C -->|no, ARP/ICMPv6| F
    C -->|no, other traffic| D
    BF -->|no| E
    BF -->|yes| GF
    B -->|malformed| G
    E --> H
    H --> I --> J
    J -->|0x0800| K
    J -->|0x86DD| L
    K --> M
    L --> M
    M -->|fourTuple match| N
    M -->|addrPort match| O
    M -->|no match| P
    N --> Q
    O --> Q
    Q --> R
```

### TX Path

```mermaid
flowchart TD
    subgraph Userspace ["Userspace (Go)"]
        A[Router processor enqueues packet]
        B[FNV-1a hash of flow ID + address header — select TX connection / queue]
        C[finishPacket — prepare link-specific header]
        D{Link type?}
        E[Resolve destination in ARP/NDP cache]
        F[Atomically load cached header, built once]
        G{MAC resolved?}
        H[Backlog — retry after resolution]
        I[Prepend header template — patch destination MAC + IP]
        J{Header built?}
        K[Build header, resolve neighbor, backlog if needed]
        L[Prepend cached header]
        M{IPv4 or IPv6?}
        N[Update total length]
        O[Recompute IPv4 header checksum in software — ~8 ns]
        P[Set UDP checksum = 0 — optional per RFC 768]
        Q[Update payload length]
        R{Selected TX conn csumOffload?}
        S[Compute only pseudo-header partial sum — ~10 ns]
        T[Compute full UDP checksum in software — ~300 ns]
        U[Enqueue to selected TX connection queue]
        V[send goroutine: batch dequeue up to batchSize]
        W[Copy packet into free UMEM frame]
        X{Selected TX conn csumOffload && IPv6?}
        Y[SubmitCsumOffload — metadata + XDP_TX_METADATA flag]
        Z[Submit — standard descriptor]
        AA[FlushTx — publish batch to kernel]
    end

    subgraph Kernel ["Kernel / NIC"]
        AC{Queue is zerocopy?}
        AD[NIC reads UMEM frame, completes requested checksum, transmits]
        AE[Kernel copies frame to SKB — normal-stack transmit]
    end

    A --> B --> C --> D
    D -->|Internal| E
    D -->|PTP| F
    E --> G
    G -->|no| H
    G -->|yes| I
    F --> J
    J -->|no| K
    J -->|yes| L
    I --> M
    K --> M
    L --> M
    M -->|IPv4| N --> O --> P
    M -->|IPv6| Q --> R
    R -->|yes| S
    R -->|no| T
    P --> U
    S --> U
    T --> U
    U --> V --> W --> X
    X -->|yes| Y
    X -->|no| Z
    Y --> AA
    Z --> AA
    AA --> AC
    AC -->|yes| AD
    AC -->|no| AE
```

### Internal vs PTP Links

```mermaid
flowchart LR
    subgraph Internal Link
        direction TB
        A1[One per underlay] --> A2[Dynamic remote — per-packet resolution]
        A2 --> A3[ARP/NDP lookup every send]
        A3 --> A4[Patch destination MAC + IP in header template]
        A4 --> A5[Supports SVC address resolution]
    end

    subgraph PTP Link
        direction TB
        B1[One per external/sibling peer] --> B2[Fixed remote known at creation]
        B2 --> B3[Resolve neighbor once — cache header atomically]
        B3 --> B4[Header rebuilt only on MAC change]
        B4 --> B5[Optional BFD liveness — external only]
    end
```

## Checksum Offload

- IPv4 TX never uses AF_XDP checksum offload. Software always recomputes the IPv4 header
  checksum and leaves the UDP checksum zero.
- IPv6 TX uses checksum offload when the selected TX connection has `csumOffload=true`.
  Userspace writes the IPv6 UDP pseudo-header seed and submits AF_XDP TX metadata. The NIC,
  which cannot see the pseudo-header fields, sums the UDP header and payload to finish the
  checksum.
- `csumOffload=true` requires all of the following:
  1. The kernel accepts UMEM TX metadata registration (`XDP_UMEM_TX_METADATA_LEN`).
  2. The bound AF_XDP queue uses zerocopy mode.
  3. The netdevice advertises AF_XDP `xsk-features: tx-checksum` through the `netdev`
     generic-netlink family.
- If any check fails, IPv6 uses a full software UDP checksum instead of emitting a seed that
  the queue would not complete.
- The decision is per selected TX connection, not per link. A multi-queue link can safely mix
  queues with different capabilities.
- UMEM may reserve TX metadata headroom even when offload is disabled. This keeps descriptor
  addressing consistent and does not imply offload is active.

## Metrics

XDP-dropped packets bypass userspace and its normal RX counters. The XDP program maintains
kernel-side counters, while AF_XDP sockets expose drop/error statistics. Separate Prometheus
metric families publish each source. On every scrape, userspace reads the eBPF map and calls
`getsockopt(XDP_STATISTICS)` once per socket; the forwarding path reads neither.

- `router_xdp_drops_total{nic, reason}` — `XDP_DROP` counts from the `drop_counters`
  `PERCPU_ARRAY` in [sockfilter.c](../../../private/underlay/ebpf/sockfilter.c).
  Reasons: `eth_malformed`, `ip_malformed`, `udp_malformed`, `fragment`.
- `router_afxdp_socket_drops_total{nic, queue, stat}` —
  `getsockopt(SOL_XDP, XDP_STATISTICS)`, where `stat` is `rx_dropped`, `rx_invalid_descs`,
  `tx_invalid_descs`, `rx_ring_full`, `rx_fill_ring_empty_descs`, or `tx_ring_empty_descs`.

Only the drop path touches `drop_counters`. The eBPF program increments the current CPU's
slot; userspace sums the per-CPU slots into one value on each scrape.

The C `DROP_REASON_*` indices must match Go's `ebpf.DropReasonNames`. `NewInterface` fails if
`drop_counters.MaxEntries != len(DropReasonNames)`.

## Test Validation

- `testdata/*.bin` contains golden Ethernet/IP/UDP frames captured from the Linux stack on a
  veth pair. Before commit, kernel-variable fields are normalized to the fixed canonical
  values emitted by this implementation, keeping the files deterministic across runs.
- Package tests compare the output of `finishPacket` with those frames byte-for-byte. They
  also compare output from the lower-level builders in `internal/headers` and
  `internal/checksum`.
- The golden files validate finalized software-checksum packets. A separate unit test verifies
  that the IPv6 checksum-offload path in `finishPacket` writes the expected pseudo-header
  seed.
- Maintainers explicitly regenerate golden files with
  `go run ./router/underlayproviders/afxdpudpip/cmd/packetgolden`; CI does not require this.
