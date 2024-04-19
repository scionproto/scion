# Router benchmark observations and predictive model

* Author(s): Jean-Christophe Hugly
* Last updated: 2024-04-10
* Discussion at: [#4408](https://github.com/scionproto/scion/issues/4408)

## TL;DR

For any hardware platform, given:

* L: the router benchmark packet length (in bytes)
* coremark: The coremark benchmark result on the platform (dimensionless)
* C: The memmove benchmark result of the platform expressed (in bytes/s)
* rate: The benchmark result of the router on the platform, using three cores (in pkts/s)
* M: an experimentally determined constant of value 18500
* I: a dimensionless number reflecting the router code's performance

At least for L = 172, the following relationship is true:

* `$I ~= (1 / coremark + (M \times L / C)) \times rate$`

## Introduction

The benchmark was ran on three configurations, the br_transit test case produced
the following data points:

* An APU2 running openwrt:

    * 4 amd cores 1GHz
    * Coremark (per core) 2821
    * memmove benchmark 1232 MiB/s (9.8 Gib/s)
    * line rate 70K pkts/s
    * Observed throughput: 44070

* A lenovo laptop running the CI benchmark:

    * 10 i7 cores 4GHz
    * Coremark (per core) 29793
    * memmove benchmark 7207 MiB/s (58 Gib/s)
    * line rate 1.4M pkts/s (veth)
    * Observed throuhgput: 613180 pkts/s

* Our CI system running the CI benchmark:

    * 4 xeon cores 3.5 GHz
    * Coremark (per core) 28707
    * memmove benchmark 9155 MiB/s (73 Gib/s)
    * line rate unobserved (veth, assumed similar to laptop)
    * Observed throuhgput: 729967 pkts/s

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

## What can be inferred from observations

### APU2

Observed:

* `$t(m) = 1s/70K$` (106 Mbyte/s, iperf3 with fast machine/nic - assuming full packets)
* `$bm(b) = 1s/44070$` (benchmark run)
* `$R = 1Gb/s$` (nominal NIC rate)
* `$C = 9.8Gb/s$` (mmbm - Go memcpy 8k blocks)

Therefore:

* `$po = t(L) - x(L) = t(m) - x(m) = 1/70K - X \times m = 1/70K - 1520 \times 8 / 1G = 0.000002126 s$`
* `$t(b) = po + x(b) = po + X \times b = 0.000002126 + 172 \times 8 / 1G = 0.000003502 s$`
* `$bm(b) = 0.000024 s$`

Since bm(b) > t(b), we can conclude that the router isn't processing at line speed, so bm(b) = r(b).
That is bm(b) reflects the router's code performance.

Therefore:

* `$r(b) = bm(b)$`
* `$ro = r(b) - p(b)$`
* `$ro = bm(b) - Y \times b = 1s / 44070 - 8 \times 172 / 9.9G = .00002396 s$`

### Laptop local test

Observed:

* `$t(m) = 1s/1.4M$` (iperf3 on non-loopback ethernet interface)
* `$bm(b) = 1s/569718$` (benchmark run)
* `$R = 17Gb/s$` (same iperf3 run as t(m). Assuming po is neglictible)
* `$C = 128Gb/s$` (mmbm - Go memcpy 8k blocks)

Therefore:

* `$po = t(L) - x(L) = t(m) - x(m) = 1/1.4M - X \times m = 1/1.4M - 1520 \times 8 / 17G$`
  `$~= 0$` (expected since we neglected po to derive R)
* `$t(b) = po + x(b) = 0 + X \times b = 172 \times 8 / 17G = 0.00000008 s$`
* `$bm(b) = 0.000001631$`

Since bm(b) > t(b) we can conclude that the router isn't processing at line speed, so bm(b) = r(b).
That is bm(b) reflects the router's code performance.

Therefore:

* `$r(b) = bm(b)$`
* `$ro = r(b) - p(b)$`
* `$ro = bm(b) - Y \times b = 1s/569718 - 8 \times 172 / 128G = .000001075 s$`

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

## Inferred router performance index

The performance index has to be such that pbm(L) is equal to bm(L) as observed in at least two experiments.
Note that only one type of forwarding is looked at - br_transit. Routers might have
different performance indices for different packet types (although only small variations are expected).

### APU2

* `$coremark = 2821$`
* `$C = 9.8Gb/s$`
* `$L = 172$`
* `$pbm(L) = 1s/44070$`
* `$I = (1 / coremark + (8 \times L / C)) / pbm(L)$`
  `$= (1 / 2821 + (8 \times 172 / 9.8G)) \times 44070$`
  `$~= 15.6$`

### Laptop

* `$coremark = 29793$`
* `$C = 58Gb/s$`
* `$L = 172$`
* `$pbm(L) = 1s/530468$`
* `$I = (1 / coremark + (8 \times L / C)) / pbm(L)$`
  `$= (1 / 29793 + (8 \times 172 / 58G)) \times 530468$`
  `$~= 17.81$`

### CI system

* `$coremark = 28707$`
* `$C = 73Gb/s$`
* `$L = 172$`
* `$pbm(L) = 1s/729967$`
* `$I = (1 / coremark + (8 \times L / C)) / pbm(L)$`
  `$= (1 / 28707 + (8 \times 172 / 73G)) \times 729967$`
  `$~= 25.81$`

...Rather bad

There is something influencing the performance that the model is not accounting for.
The CI system has a coremark similar to that of the laptop but much faster memory copy.
So memory copy may have a greater influence than the model is accouting for. We seem to
be unwittingly attributing some of the memory performance to the router's implementation.

That's as close as I am able to get at the moment.