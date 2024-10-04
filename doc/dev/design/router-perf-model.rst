**************************************************
Router benchmark observations and predictive model
**************************************************

-  Author(s): Jean-Christophe Hugly
-  Last updated: 2024-04-22
-  Status: **Active**
-  Discussion at: :issue:`4408`

TL;DR
=====

For any hardware platform, given:

-  :math:`L`: the router benchmark packet length (in bytes)
-  coremark: The coremark benchmark result on the platform
   (dimensionless)
-  :math:`C`: The memmove benchmark result of the platform expressed (in bytes/s)
-  rate: The benchmark result of the router on the platform, using three cores (in pkts/s)
-  :math:`M`: an experimentally determined constant of value 400
-  :math:`I`: a dimensionless number reflecting the router code’s performance

At least for :math:`L` = 172, the following relationship is true:

.. math::

  I ~= (1 / coremark + (M \times L / C)) \times rate

Introduction
============

The benchmark was ran on three configurations, the br_transit test case
produced the following data points:

-  An APU2 running openwrt:

   -  4 amd cores 1GHz
   -  Coremark (per core) 3044
   -  memmove benchmark 248 MiB/s (1.9 Gib/s)
   -  line rate 70K pkts/s
   -  Observed throughput: 45377

-  A lenovo laptop running the CI benchmark:

   -  10 i7 cores 4GHz
   -  Coremark (per core) 29861
   -  memmove benchmark 3928 MiB/s (31 Gib/s)
   -  line rate 1.4M pkts/s (veth)
   -  Observed throuhgput: 639764 pkts/s

-  Our CI system running the CI benchmark:

   -  4 xeon cores 3.5 GHz
   -  Coremark (per core) 28659
   -  memmove benchmark 8102 MiB/s (64 Gib/s)
   -  line rate unobserved (veth, assumed similar to laptop)
   -  Observed throuhgput: 736357 pkts/s

Important: all benchmarks have been run with only 3 cores assigned to
the router. The cores are chosen by the benchmarking program to be of
the same type (i.e. no mix of performance and energy-efficient cores).
Hyperthreading is not used.

See “The problem with the influence of core count”.

Where might the time go
=======================

With a single core, the time processing a packet is presumed spend as follows...

Variables:

-  let :math:`b` = benchmark packet size (152)
-  let :math:`e` = empty packet size (34)
-  let :math:`m` = max packet size (1520)
-  let :math:`po` = packet overhead time in seconds
-  let :math:`L` = the length of a given packet [bytes]
-  let :math:`x(L)` = packet-length dependent xmit time [s]
-  let :math:`t(L)` = total packet transmission time for :math:`L` [s]
-  let :math:`R` = nominal wire rate in decoded [bit/s]
-  let :math:`X` = line slowness [seconds/byte]
-  let :math:`bm(L)` = total benchmark packet processing time (including transmission and pkt overhead) [s]
-  let :math:`ro` = router overhead [time added by processing one packet in the router] [s]
-  let :math:`p(L)` = packet-length dependent router processing time for :math:`L` [s]
-  let :math:`r(L)` = total processing time in router for :math:`L` [s]
-  let :math:`C` = nominal copy rate in [bit/s]
-  let :math:`Y` = copy slowness [seconds/byte]

Transmission:

-  assume :math:`x(L) = X \times L` [X is s/byte]
-  assume :math:`t(L) = po + x(L)`
-  assume :math:`X = 8/R`
-  po is unknown

Router:

-  assume :math:`p(L) = Y \times L` [Y is s/byte]
-  assume :math:`r(L) = ro + p(L)`
-  assume :math:`Y = 8/C` [that is, the length-dependent processing time
   is ~copying the packet]
-  ro is unknown

Aggregate:

-  assume :math:`bm(L) = MAX(r(L), t(L))`

What can be inferred from observations
======================================

APU2
----

Observed:

-  :math:`t(m) = 1s/70K` (106 Mbyte/s, iperf3 with fast machine/nic -- assuming full packets)
-  :math:`bm(b) = 1s/45377` (benchmark run)
-  :math:`R = 1Gb/s` (nominal NIC rate)
-  :math:`C = 1.9Gb/s` (mmbm - Go memmove small packets)

Therefore:

-  :math:`po = t(L) - x(L) = t(m) - x(m) = 1/70K - X \times m = 1/70K - 1520 \times 8 / 1G`
   :math:`= 0.000002126 s`
-  :math:`t(b) = po + x(b) = po + X \times b = 0.000002126 + 172 \times 8 / 1G = 0.000003502 s`
-  :math:`bm(b) = 0.000024 s`

Since :math:`bm(b) > t(b)`, we can conclude that the router isn’t processing at line speed,
so :math:`bm(b) = r(b)`. That is :math:`bm(b)` reflects the router’s code performance.

Therefore:

-  :math:`r(b) = bm(b)`
-  :math:`ro = r(b) - p(b)`
-  :math:`ro = bm(b) - Y \times b = 1s / 45377 - 8 \times 172 / 1.9G = 0.00002131 s`

Laptop local test
-----------------

Observed:

-  :math:`t(m) = 1s/1.4M` (iperf3 on non-loopback ethernet interface)
-  :math:`bm(b) = 1s/639764` (benchmark run)
-  :math:`R = 17Gb/s` (same iperf3 run as t(m). Assuming po is neglictible)
-  :math:`C = 31Gb/s` (mmbm - Go memmove small packets)

Therefore:

-  :math:`po = t(L) - x(L) = t(m) - x(m) = 1/1.4M - X \times m = 1/1.4M - 1520 \times 8 / 17G`
   :math:`~= 0` (expected since we neglected po to derive R)
-  :math:`t(b) = po + x(b) = 0 + X \times b = 172 \times 8 / 17G = 0.00000008 s`
-  :math:`bm(b) = 0.000001563`

Since :math:`bm(b) > t(b)` we can conclude that the router isn’t processing at line speed,
so :math:`bm(b) = r(b)`. That is :math:`bm(b)` reflects the router’s code performance.

Therefore:

-  :math:`r(b) = bm(b)`
-  :math:`ro = r(b) - p(b)`
-  :math:`ro = bm(b) - Y \times b = 1s/639764 - 8 \times 172 / 31G = 0.000001519 s`

Assumption of less-than-line-rate
---------------------------------

The case where the line rate is low enough to be the bottleneck isn’t
very interresting. Because it is so clearly not the case with the
hardware available to us, we will consider only the case where the wire
is faster than the router.

Tentative predictive model
==========================

Initial assumptions
-------------------

Variables:

-  let :math:`pbm(L)` = predicted benchmark processing time for length :math:`L`
-  let :math:`pt(L)` = predicted total transmission time for length :math:`L`
-  let :math:`pp(L)` = predicted lenght-dependent processing time for :math:`L`
-  let :math:`pro` = predicted router per-packet overhead
-  let :math:`N` = The number of cores devote to packet processing
-  let :math:`I` = The router’s code performance index; a measure of the code’s efficiency

We assume that the length-independent time spent processing is inverse
proportional to:

-  coremark
-  :math:`N`
-  :math:`I`

In all likelyness each packet is processed by one core, but we do not
known that for sure. So, for now, we’re assuming that N packets are
going to be processed by N cores as fast as 1 packet by one core (the
difference, if any, would be an effect of the code’s quality and so
reflected by the performance index. So, the statistical processing time
per packet is 1/N that of single core processing.

We assume that the length-dependent time processing the packet is proportional to:

-  The length of the packet

...and inverse proportional to:

-  :math:`I` (in this case, reflecting how little copying is done)
-  :math:`C`, The memcpy rate.

Model
-----

From our assumptions, (and single I simplification) we have:

-  :math:`pro = 1 / (I \times coremark)`
-  :math:`pp(L) = 8 \times L / (I \times C)`
-  :math:`pbm(L) = pro + pp(L)`
   :math:`= 1 / (I \times coremark) + 8 \times L / (I \times C)`
   :math:`= (1 / I) \times (1 / coremark) + (8 \times L / C))`
-  :math:`I = (1 / coremark + (8 \times L / C)) / pbm(L)`

Since we ran the same router on both benchmarking platform, we should be
able to infer the same I from the benchmark result and hadrware
characteristics. (or, at least, close).

If so, that’s our platform independent performance index. That is, given
a benchmark on any platform, with known C and coremark, we can find this
number and use it to predict the performance of the same code on any
other platform with known C and coremark.

The influence of caches and TLBs
--------------------------------

Efforts to improve the precision of the mmbm benchmark (which attempts
to measure :math:`C` showed that trying to model the behavior of caches
and TLBs is extremely challenging. For example:

-  The cache and TLB benefits do not disappear as the working set
   exceeds the cache/TLB size. Nor are those benefits fully realized
   while the working set remains within the cache size. The precise
   behavior varies by CPU model.
-  Page table walks polute the cache for some CPU models, but others
   have a hidden cache exclusiveley for page table entries.
-  Copying many 1 byte packets within a 128 pages arena takes
   consistently more time than within an 8192 pages arena in at least
   one CPU model. The reason for this remains a mystery.

Multiway associative caches, combined with mostly secret replacement
policies, undocumented caches, and intractable activity by the OS and
the Go runtime make it extremely challenging to predict how a given
workload (even a synthetic one) will perform on a given CPU. So far,
this has not been achieved.

As a distant second best, the mmbm benchmark only measures the copy
speed in a handful of cases. For the purpose of modeling we use one case
that is modeled after what the reference router does under benchmark. It
is expected to cause non-temporal TLB access but a 100% hit rate on the
L2 data cache, but that is not reflected reliably in the router’s
benchmark results.

By relying on these simple macroscopic metric and by tuning empirical
parameters, we may be able to better approximate a cross-hardware router
performance index. To that end we need to find or tune two additional
parameters M and N such that:

:math:`I = (1 / coremark + M * (8 \times L / C) + N) / pbm(L)`

M represents the proportion in wich memory performance and arithmetic
performance contribute to throughput. Such a ratio needs to exist for a
translatable performance index.

N represents a fixed hardware-dependent per-packet cost that, judging by
the above results the model has failed to anticipate. We could speculate
that this cost is related to interacting with network interfaces. If
that is the case, a measure of it needs to be incorporated in our suite
of microbenchmarks.

Given a known N for three different systems, we could probably infer M.
However, N is a property of each platform. It has to be measured.

Inferred router performance index
=================================

The performance index has to be such that pbm(L) is equal to bm(L) as
observed in at least two experiments. Note that only one type of
forwarding is looked at - br_transit. Routers might have different
performance indices for different packet types (although only small
variations are expected).

If we ignore M and N for now, (i.e. M = 1, N = 0), we have the
following:

.. _apu2-1:

APU2
----

-  :math:`coremark = 3044`
-  :math:`C = 1.9Gb/s`
-  :math:`L = 172`
-  :math:`pbm(L) = 1s/45377`
-  :math:`I = (1 / coremark + (8 \times L / C)) / pbm(L)`
   :math:`= (1 / 3044 + (8 \times 172 / 1.9G)) \times 45377`
   :math:`~= 14.93`

Laptop
------

-  :math:`coremark = 29851`
-  :math:`C = 31Gb/s`
-  :math:`L = 172`
-  :math:`pbm(L) = 1s/639764`
-  :math:`I = (1 / coremark + (8 \times L / C)) / pbm(L)`
   :math:`= (1 / 29851 + (8 \times 172 / 31G)) \times 639864`
   :math:`~= 21.46`

CI system
---------

-  :math:`coremark = 28659`
-  :math:`C = 64Gb/s`
-  :math:`L = 172`
-  :math:`pbm(L) = 1s/736357`
-  :math:`I = (1 / coremark + (8 \times L / C)) / pbm(L)`
   :math:`= (1 / 28659 + (8 \times 172 / 64G)) \times 736357`
   :math:`~= 25.7`

...Not close.

The CI system has a coremark similar to that of the laptop but much
faster memory copy. So memory copy may have a greater influence than
coremark. In other words, the hypothetical M value (see the previous
section) is much greater than 1. For example, assuming N=0, a value of
400 for M yields performance indices of 28, 33 and 32 for APU2, the
laptop, and the CI system, respectively. So, tuning is at least
possible. This is purely speculative, though. We do not know if N can be
neglected.

Application to router improvement
---------------------------------

Some of the lessons learned during the benchmarking effort:

-  The router performance is probably dominated by TLB misses.
-  The router keeps 9K buffers, which makes 3/4 of all buffers
   missaligned. That extra 1k is paid with an extra TLB miss.
-  Small packets are dispersed over large buffers. Each small packet
   requires at least one page access.
-  At steady state, all buffers are eventually occupied, therefore we
   cycle through the whole set. Since that set is much larger than the
   cache, we loose all temporal locality: all packets get evicted from
   the cache, possibly more than once, during processing.
