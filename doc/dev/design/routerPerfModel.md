# Router benchmark observations and predictive model

* Author(s): Jean-Christophe Hugly
* Last updated: 2024-04-22
* Discussion at: [#4408](https://github.com/scionproto/scion/issues/4408)

## TL;DR

For any hardware platform, given:

* L: the router benchmark packet length (in bytes)
* coremark: The coremark benchmark result on the platform (dimensionless)
* C: The memmove benchmark result of the platform expressed (in bytes/s)
* rate: The benchmark result of the router on the platform, using three cores (in pkts/s)
* M: an experimentally determined constant of value 400
* I: a dimensionless number reflecting the router code's performance

At least for L = 172, the following relationship is true:

* `$I ~= (1 / coremark + (M \times L / C)) \times rate$`

## Introduction

The benchmark was ran on three configurations, the br_transit test case produced
the following data points:

* An APU2 running openwrt:
    * 4 amd cores 1GHz
    * Coremark (per core) 3044
    * memmove benchmark 248 MiB/s (1.9 Gib/s)
    * line rate 70K pkts/s
    * Observed throughput: 45377

* A lenovo laptop running the CI benchmark:

    * 10 i7 cores 4GHz
    * Coremark (per core) 29861
    * memmove benchmark 3928 MiB/s (31 Gib/s)
    * line rate 1.4M pkts/s (veth)
    * Observed throuhgput: 639764 pkts/s

* Our CI system running the CI benchmark:

    * 4 xeon cores 3.5 GHz
    * Coremark (per core) 28659
    * memmove benchmark 8102 MiB/s (64 Gib/s)
    * line rate unobserved (veth, assumed similar to laptop)
    * Observed throuhgput: 736357 pkts/s

Important: all benchmarks have been run with only 3 cores assigned to the router. The cores are
chosen by the benchmarking program to be of the same type (i.e. no mix of performance and
energy-efficient cores). Hyperthreading is not used.

See "The problem with the influence of core count".

## Where might the time go

With a single core, the time processing a packet is presumed spend as follows...

Variables:

* let b = benchmark packet size (152)
* let e = empty packet size (34)
* let m = max packet size (1520)
* let po = packet overhead time in seconds
* let L = the length of a given packet [bytes]
* let x(L) = packet-length dependent xmit time [s]
* let t(L) = total packet transmission time for L [s]
* let R = nominal wire rate in decoded [bit/s]
* let X = line slowness [seconds/byte]
* let bm(L) = total benchmark packet processing time (including transmission and pkt overhead) [s]
* let ro = router overhead [time added by processing one packet in the router] [s]
* let p(L) = packet-length dependent router processing time for L [s]
* let r(L) = total processing time in router for L [s]
* let C = nominal copy rate in [bit/s]
* let Y = copy slowness [seconds/byte]

Transmission:

* assume `$x(L) = X \times L$` [X is s/byte]
* assume `$t(L) = po + x(L)$`
* assume `$X = 8/R$`
* po is unknown

Router:

* assume `$p(L) = Y \times L$` [Y is s/byte]
* assume `$r(L) = ro + p(L)$`
* assume `$Y = 8/C$` [that is, the length-dependent processing time is ~copying the packet]
* ro is unknown

Aggregate:

* assume `$bm(L) = MAX(r(L), t(L))$`

## What can be inferred from observations (NUMBERS TO BE UPDATED)

### APU2

Observed:

* `$t(m) = 1s/70K$` (106 Mbyte/s, iperf3 with fast machine/nic - assuming full packets)
* `$bm(b) = 1s/45377$` (benchmark run)
* `$R = 1Gb/s$` (nominal NIC rate)
* `$C = 1.9Gb/s$` (mmbm - Go memmove small packets)

Therefore:

* `$po = t(L) - x(L) = t(m) - x(m) = 1/70K - X \times m = 1/70K - 1520 \times 8 / 1G = 0.000002126 s$`
* `$t(b) = po + x(b) = po + X \times b = 0.000002126 + 172 \times 8 / 1G = 0.000003502 s$`
* `$bm(b) = 0.000024 s$`

Since bm(b) > t(b), we can conclude that the router isn't processing at line speed, so bm(b) = r(b).
That is bm(b) reflects the router's code performance.

Therefore:

* `$r(b) = bm(b)$`
* `$ro = r(b) - p(b)$`
* `$ro = bm(b) - Y \times b = 1s / 45377 - 8 \times 172 / 1.9G = 0.00002131 s$`

### Laptop local test

Observed:

* `$t(m) = 1s/1.4M$` (iperf3 on non-loopback ethernet interface)
* `$bm(b) = 1s/639764$` (benchmark run)
* `$R = 17Gb/s$` (same iperf3 run as t(m). Assuming po is neglictible)
* `$C = 31Gb/s$` (mmbm - Go memmove small packets)

Therefore:

* `$po = t(L) - x(L) = t(m) - x(m) = 1/1.4M - X \times m = 1/1.4M - 1520 \times 8 / 17G$`
  `$~= 0$` (expected since we neglected po to derive R)
* `$t(b) = po + x(b) = 0 + X \times b = 172 \times 8 / 17G = 0.00000008 s$`
* `$bm(b) = 0.000001563$`

Since bm(b) > t(b) we can conclude that the router isn't processing at line speed, so bm(b) = r(b).
That is bm(b) reflects the router's code performance.

Therefore:

* `$r(b) = bm(b)$`
* `$ro = r(b) - p(b)$`
* `$ro = bm(b) - Y \times b = 1s/639764 - 8 \times 172 / 31G = 0.000001519 s$`

### Assumption of less-than-line-rate

The case where the line rate is low enough to be the bottleneck isn't very interresting.
Because it is so clearly not the case with the hardware available to us, we will consider
only the case where the wire is faster than the router.

## Tentative predictive model

### Initial assumptions

Variables:

* let pbm(L) = predicted benchmark processing time for length L
* let pt(L) = predicted total transmission time for length L
* let pp(L) = predicted lenght-dependent processing time for L
* let pro = predicted router per-packet overhead
* let N = The number of cores devote to packet processing
* let I = The router's code performance index; a measure of the code's efficiency

We assume that the length-independent time spent processing is inverse proportional to:

* coremark
* N
* I

In all likelyness each packet is processed by one core, but we do not known that for sure.
So, for now, we're assuming that N packets are going to be processed by N cores as fast as
1 packet by one core (the difference, if any, would be an effect of the code's quality
and so reflected by the performance index. So, the statistical processing time per packet
is 1/N that of single core processing.

We assume that the length-dependent time processing the packet is proportional to:

* The length of the packet

...and inverse proportional to:

* I (in this case, reflecting how little copying is done)
* C, The memcpy rate.

Using a single performance index is a simplication: the same performance index could be
calculated for code that copies little but proceses slowly and for code that does the opposite,
while they would perform differently on different hardware or with different packet sizes.
We will address this by splitting the two performance components once we have enough
experimental data (starting with running the benchmark at more than 1 packet size).

### The problem with the influence of core count

The goals of this model, along with the benchmark process, is to assign a performance index
that allows the comparison of diverse router implementations. As a result we cannot have a model
that makes assumptions about the implementation. (For example, how many cores are dedicated
to each part of the processing). If the model were to take that into account, it would require
detailed input about each implementation's design that is difficult to anticipate.

Without any such knowledge, it is not possible to predict how varying the number of core
allocated to the router will affect a given router's performance. So, this aspect is, for now,
excluded from the modeling effort. Instead, this model must assign a performance index and
make predictions for a standardized number of cores. i.e. the benchmark needs to be run
with a specific number of cores assigned to the router. To ensure that we can run the benchmark
on a large variety of platforms, we keep this number low. Currently this is 3. Should the need
arise to compare and predict the performance with more cores, we will maintain several categories
of results which are not necessarily comparable accross categories.

This means that a router may be tuned to perform at its best with 3 cores. We have to accept
this. It is unlikely that a router would be implementated solely for the prupose of having
the best number in our benchmark. More likely, the router self-tunes to the number of available
cores. (Note that the current implementation tunes itself quite badly for 3 cores - a fact
which revealed the difficulty in comparing results accross core-counts).

Therefore, in what follows, N is not an input to the model (it is replaced with the
constant 1).

### Model

From our assumptions, (and single I simplification) we have:

* `$pro = 1 / (I \times coremark)$`
* `$pp(L) = 8 \times L / (I \times C)$`
* `$pbm(L) = pro + pp(L)$`
  `$= 1 / (I \times coremark) + 8 \times L / (I \times C)$`
  `$= (1 / I) \times (1 / coremark) + (8 \times L / C))$`
* `$I = (1 / coremark + (8 \times L / C)) / pbm(L)$`

Since we ran the same router on both benchmarking platform, we should be able to infer the same
I from the benchmark result and hadrware characteristics. (or, at least, close).

If so, that's our platform independent performance index. That is, given a benchmark on any platform,
with known C and coremark, we can find this number and use it to predict the performance of the same
code on any other platform with known C and coremark.

### The influence of caches and TLBs

Efforts to improve the precision of the mmbm benchmark (which attempts to measure `$C$`
showed that trying to model the behavior of caches and TLBs is extremely challenging.
For example:

* The cache and TLB benefits do not disappear as the working set exceeds the cache/TLB
  size. Nor are those benefits fully realized while the working set remains within the
  cache size. The precise behavior varies by CPU model.
* Page table walks polute the cache for some CPU models, but others have a hidden
  cache exclusiveley for page table entries.
* Copying many 1 byte packets within a 128 pages arena takes consistently more time
  than within an 8192 pages arena in at least one CPU model. The reason for this remains
  a mystery.

Multiway associative caches, combined with mostly secret replacement policies, undocumented
caches, and intractable activity by the OS and the Go runtime make it extremely challenging
to predict how a given workload (even a synthetic one) will perform on a given CPU. So far,
this has not been achieved.

As a distant second best, the mmbm benchmark only measures the copy speed in a handful of
cases. For the purpose of modeling we use one case that is modeled after what the reference
router does under benchmark. It is expected to cause non-temporal TLB access but a 100% hit
rate on the L2 data cache, but that is not reflected reliably in the router's benchmark results.

By relying on these simple macroscopic metric and by tuning empirical parameters, we may
be able to better approximate a cross-hardware router performance index. To that end we need to
find or tune two additional parameters M and N such that:

`$I = (1 / coremark + M * (8 \times L / C) + N) / pbm(L)$`

M represents the proportion in wich memory performance and arithmetic performance
contribute to throughput. Such a ratio needs to exist for a translatable performance index.

N represents a fixed hardware-dependent per-packet cost that, judging by the above results
the model has failed to anticipate. We could speculate that this cost is related to interacting
with network interfaces. If that is the case, a measure of it needs to be incorporated in our
suite of microbenchmarks.

Given a known N for three different systems, we could probably infer M. However, N is a
property of each platform. It has to be measured.

## Inferred router performance index

The performance index has to be such that pbm(L) is equal to bm(L) as observed in at least two experiments.
Note that only one type of forwarding is looked at - br_transit. Routers might have
different performance indices for different packet types (although only small variations are expected).

If we ignore M and N for now, (i.e. M = 1, N = 0), we have the following:

### APU2

* `$coremark = 3044$`
* `$C = 1.9Gb/s$`
* `$L = 172$`
* `$pbm(L) = 1s/45377$`
* `$I = (1 / coremark + (8 \times L / C)) / pbm(L)$`
  `$= (1 / 3044 + (8 \times 172 / 1.9G)) \times 45377$`
  `$~= 14.93$`

### Laptop

* `$coremark = 29851$`
* `$C = 31Gb/s$`
* `$L = 172$`
* `$pbm(L) = 1s/639764$`
* `$I = (1 / coremark + (8 \times L / C)) / pbm(L)$`
  `$= (1 / 29851 + (8 \times 172 / 31G)) \times 639864$`
  `$~= 21.46$`

### CI system

* `$coremark = 28659$`
* `$C = 64Gb/s$`
* `$L = 172$`
* `$pbm(L) = 1s/736357$`
* `$I = (1 / coremark + (8 \times L / C)) / pbm(L)$`
  `$= (1 / 28659 + (8 \times 172 / 64G)) \times 736357$`
  `$~= 25.7$`

...Not close.

The CI system has a coremark similar to that of the laptop but much faster memory copy.
So memory copy may have a greater influence than coremark. In other words, the hypothetical M
value (see the previous section) is much greater than 1. For example, assuming N=0, a value of
400 for M yields performance indices of 28, 33 and 32 for APU2, the laptop, and the CI system,
respectively. So, tuning is at least possible. This is purely speculative, though. We do not
know if N can be neglected.

### Application to router improvement

Some of the lessons learned during the benchmarking effort:

* The router performance is probably dominated by TLB misses.
* The router keeps 9K buffers, which makes 3/4 of all buffers missaligned. That extra 1k is paid with
  an extra TLB miss.
* Small packets are dispersed over large buffers. Each small packet requires at least one page access.
* At steady state, all buffers are eventually occupied, therefore we cycle through the whole set. Since
  that set is much larger than the cache, we loose all temporal locality: all packets get evicted from
  the cache, possibly more than once, during processing.
