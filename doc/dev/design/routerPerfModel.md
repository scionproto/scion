# Router benchmark observations and predictive model

## TL;DR

For any hardware platform, given:
* l: the router benchmark packet length (in bytes)
* coremark: The coremark benchmark result on the platform (dimensionless)
* C: The memmove benchmark result of the platform expressed (in bytes/s)
* rate: The benchmark result of the router on the platform, using three cores (in pkts/s)
* M: an experimentally determined constant of value 18500
* I: a dimensionless number reflecting the router code's performance

At least for l == 172, the following relationship is true:
I ~= (1 / coremark + (M * l / C)) * rate

## Introduction

The benchmark was ran on three configurations, the br_transit test case produced
the following data points:

* An APU2 running openwrt:
  * 4 amd cores 1GHz
  * Coremark (per core) 2972
  * memmove benchmark 1235 MiB/s (9.8 Gib/s)
  * line rate 70K pkts/s
  * Observed throughput: 41487

* A lenovo laptop running the CI benchmark:
  * 3 i7 cores 4GHz
  * Coremark (per core) 29902
  * memmove benchmark 16218 MiB/s (129 Gib/s)
  * line rate 1.4M pkts/s (veth)
  * Observed throuhgput: 613180 pkts/s

* Our CI system running the CI benchmark:
  * 4 xeon cores 3.5 GHz
  * Coremark (per core) 28690
  * memmove benchmark 23007 MiB/s (184 Gib/s)
  * line rate unobserved (veth, assumed similar to laptop)
  * Observed throuhgput: 736797 pkts/s

Important: all benchmarks have been run with only 3 cores assigned to the router.
See "The problem with the influence of core count".

## Where might the time go

With a single core, the time processing a packet is presumed spend as follows...

Variables:
* let b == benchmark packet size (152)
* let e == empty packet size (34)
* let m == max packet size (1520)
* let po == packet overhead time in seconds
* let l == the length of a given packet [bytes]
* let x(l) == packet-length dependent xmit time [s]
* let t(l) == total packet transmission time for l [s]
* let R == nominal wire rate in decoded [bit/s]
* let X == line slowness [seconds/byte]
* let bm(l) == total benchmark packet processing time (including transmission and pkt overhead) [s]
* let ro == router overhead [time added by processing one packet in the router] [s]
* let p(l) == packet-length dependent router processing time for l [s]
* let r(l) == total processing time in router for l [s]
* let C == nominal copy rate in [bit/s]
* let Y == copy slowness [seconds/byte]

Transmission:
* assume x(l) == X*l [X is s/byte]
* assume t(l) == po + x(l)
* assume X == 8/R
* po is unknown

Router:
* assume p(l) == Y*l [Y is s/byte]
* assume r(l) == ro + p(l)
* assume Y == 8/C [assuming that length-dependent processing time is ~copying the packet]
* ro is unknown

Aggregate:
* assume bm(l) == MAX(r(l), t(l))

## What can be inferred from observations

### APU2

Observed:
* t(m) == 1s/70K (106 Mbyte/s, iperf3 with fast machine/nic - assuming full packets)
* bm(b) == 1s/41487 (benchmark run)
* R = 1Gb/s (nominal NIC rate)
* C = 9.8Gb/s (mmbm - Go memcpy 8k blocks)

Therefore:
* po = t(l) - x(l) = t(m) - x(m) = 1/70K - X*m = 1/70K - 1520 * 8 / 1G = 0.000002126 s
* t(b) = po + x(b) = po + X*b = 0.000002126 + 172 * 8 / 1G = 0.000003502 s
* bm(b) = 0.000024 s

Since bm(b) > t(b), we can conclude that the router isn't processing at line speed, so bm(b) == r(b).
That is bm(b) reflects the router's code performance.

Therefore:
* r(b) == bm(b)
* ro = r(b) - p(b)
* ro = bm(b) - Y*b = 1s / 41487 - 8 * 172 / 9.9G = .00002396 s

### Laptop local test:

Observed:
* t(m) = 1s/1.4M (iperf3 on non-loopback ethernet interface)
* bm(b) = 1s/613180 (benchmark run)
* R = 17Gb/s (same iperf3 run as t(m). Assuming po is neglictible).
* C = 128Gb/s (mmbm - Go memcpy 8k blocks)

Therefore:
* po = t(l) - x(l) = t(m) - x(m) = 1/1.4M - X*m = 1/1.4M - 1520 * 8 / 17G
  ~= 0 (expected since we neglected po to derive R)
* t(b) = po + x(b) = 0 + X*b = 172 * 8 / 17G = 0.00000008 s
* bm(b) = 0.000001631

Since bm(b) > t(b) we can conclude that the router isn't processing at line speed, so bm(b) == r(b).
That is bm(b) reflects the router's code performance.

Therefore:
* r(b) = bm(b)
* ro = r(b) - p(b)
* ro = bm(b) - Y*b = 1s/613180 - 8 * 172 / 128G = .000001075 s

### Assumption of less-than-line-rate

The case where the line rate is low enough to be the bottleneck isn't very interresting.
Because it is so clearly not the case with the hardware available to us, we will consider
only the case where the wire is faster than the router.

## Tentative predictive model

### Initial assumptions

Variables:
* let pbm(l) = predicted benchmark processing time for length l
* let pt(l) = predicted total transmission time for length l
* let pp(l) = predicted lenght-dependent processing time for l
* let pro = predicted router per-packet overhead
* let N = The number of cores devote to packet processing.
* let I = The router's code performance index; a measure of the code's efficiency.

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
* pro = 1 / (I * coremark)
* pp(l) = 8 * l / (I * C)
* pbm(l) = pro + pp(l)
  = 1 / (I * coremark) + 8 * l / (I * C)
  = (1 / I) * (1 / coremark) + (8 * l / C))
* I = (1 / coremark + (8 * l / C)) / pbm(l)

Since we ran the same router on both benchmarking platform, we should be able to infer the same
I from the benchmark result and hadrware characteristics. (or, at least, close).

If so, that's our platform independent performance index. That is, given a benchmark on any platform,
with known C and coremark, we can find this number and use it to predict the performance of the same
code on any other platform with known C and coremark.

## Inferred router performance index

The performance index has to be such that pbm(l) is equal to bm(l) as observed in at least two experiments.
Note that only one type of forwarding is looked at - br_transit. Routers might have
different performance indices for different packet types (although only small variations are expected).

### APU2

* coremark = 2972
* C = 9.8Gb/s
* l = 172
* pbm(l) = 1s/43469
* I = (1 / coremark + (8 * l / C)) / pbm(l)
  = (1 / 2972 + (8 * 172 / 9.8G)) * 43469
  ~= 14.6

### Laptop

* coremark = 29902
* C = 129Gb/s
* l = 172
* pbm(l) = 1s/530468
* I = (1 / coremark + (8 * l / C)) / pbm(l)
  = (1 / 29882 + (8 * 172 / 129G)) * 530468
  ~= 17.75

~18% appart...Not great

### Refining the model

So, what if the single performance index is too simple? That is, what
if the performance of memcopy has more influence? To find out, we injected a coeficient
M for the memcpy impact (The more memcpy matters the higher the performance index
for a given throughput):

So, the I and pbm relationship becomes:

I = (1 / coremark + (M * 8 * l / C)) / pbm(l)
or
pbm(l) = (1 / coremark + (M * 8 * l / C)) / I

To slightly improve readability of what follows, let:
* rate1 = 1/pbm(l) for APU2
* rate2 = 1/pbm(l) for laptop
* coremark1 = coremark of APU2
* coremark2 = coremark of laptop
* C1 = memcpy speed of APU2
* C2 = memcpy speed of laptop

To have a common performance index between the APU2 and laptop platforms, we need:
* (1/coremark1 + (M * 8 * l / C1)) / pbm1 = (1/coremark2 + (M * 8 * l / C2)) / pbm2
* 1/(coremark1 * pbm1) + M * 8 * l /(C1 * pbm1) = 1/(coremark2 * pbm2) + M * 8 * l /(C2 * pbm2)
* 1/(coremark1 * pbm1) - 1/(coremark2 * pbm2) =  M * 8 * l / (C2 * pbm2) - M * 8 * l / (C1 * pbm1)
* 1/(coremark1 * pbm1) - 1/(coremark2 * pbm2) = M * 8 * l * ( 1 / (C2 * pbm2) - 1 / (C1 * pbm1) )
* M = (1/(coremark1 * pbm1) - 1/(coremark2 * pbm2)) / ( 8 * l * ( 1 / (C2 * pbm2) - 1 / (C1 * pbm1)
* M = (rate1/coremark1 - rate2/coremark2) / (8*172*(rate2/C2 - rate1/C1))
* M ~= 6996

With that M value and new I, for our two platforms we have:
* APU2: I = 57.32
* Laptop: I 57.32
Sanity check passed.

### Thrid platform

Since we fit M exactly to the data we had, we need to confront it with the observed data from
a third platform. Using M and the CI system's data, we find:

* I = 64.23

~= 11% appart. That's better than before introducing M, but not entirely satisfactory.

### Shameless fudging

Since the model is necessarily an appromxiation, we should try and improve that approximation
rather than trying to match existing data samples exactly. To that end, we can find a value of M
that doesn't yeild a equal I for any pair of platforms but minimizes the differences instead.

A value M=18500 yields the following I values:
* APU2: I = 127.54
* Laptop: I = 122.42
* CI system: I = 127.62

So, at most 4% appart. We shall be content with that for now and can only whish that
data from a fourth platform isn't going to dispell that magic completely.

The method used to find that number is left to the reader's imagination.

## Predictive quality of the index

Applying the index measured on one platform to the other, we get
the following predictions:

APU2 predicted throughput, using Laptop's index:
* pbm = 1 / (122.42 * coremark) + M * 8 * l / C
      = 1 / (122 * 2972) + 18500 * 8 * 172 / 9.8G
	  = .00002405
* throughput = 41580
* underestimated by ~4%

Laptop predicted throughput, using APU2's index:
* pbm = 1 / (127 * coremark) + M * 8 * l / C
*     = 1 / (127 * 29866 * 3) + 18500 8 * 172 / 128G
*     = 0.000001817
* throughput = 550357
* overestimated by ~4% 
