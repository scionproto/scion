# Path Quality Aware Beaconing

This document ountlines the path quality aware beconing algorithm proposed by Ali and Adrian [1], and how it is implemented in the SCION codebase. 

* Author(s): Silas Gyger
* Status: draft
* Last edited: 2021-12-xx

## Algorithm
### Background
During core beaconing, core ASs continuously have to decide which beacons to forward to which interfaces in order to keep the message complexity sufficiently low. 

Traditional algorithms have focussed on selecting paths with low hop count[2] or high diversity w.r.t. links travelled [3]. The goal of either is to provide each AS with a high quality set of paths to every other AS, such that their target application can (hopefully) select one that suits its needs.

In certain situations, it's already known which path qualities end hosts will be looking for when they connect to a specific interface. For instance, a internet video call service provider will already know that all of its customers will be looking for low-latency connections to its video call endpoint. Offering a selection of paths with varying qualities in this case is an uncessary overhead. The following document outlines a mechanism wich allows core ASs to define qualities for beacons originating from defined applications for which the beaconing process should optimize for; the end result of the beaconing process should be that all parties will end up with paths that are optimal with respect to this quality to that target application, and have diversity at most in other qualities.

### Path granularity

Unlike in previous algorithms, AS-level granularity becomes insufficent to determine the quality of a path with respect to many metrics. For instance, a path optimized for latency will have different quality metric in this respect when forwarded to a neighbouring AS in Munich as opposed to Sidney. However, both Sidney and Munich might benefit from receiving the beacons, as they might still be the fastest route to either place. 

### Linearity of metrics

We expect metrics to scale linearly with the path; i.e. for a path $a \rightarrow b \rightarrow c$ and metric $f$, we assume $f(a \rightarrow b \rightarrow c) \approx f(a \rightarrow b) + f(b\rightarrow c)$. Hence, if we intend to sent the best $N$ paths to every interface group, we can simplify the problem as follows:

* of the best $N$ paths, the parts leading to the ingress interface will be among the best $N$ paths leading just to that interface
* of the best $N$ paths, the parts leading to a specific interface group willl be among the best $N$ paths leading to that interface group
* of the best $N$ paths, their inter-AS links will be among the $N$ best inter-AS links away from the given interface group

Hence we can first pick the $N$ best paths from each of these subproblems before putting them together.

> TODO: Might it make sense to allow ASs to define groups of interfaces that are similar in a specific metric TO THEIR NEIGHBOUR? E.g. Swisscom might define that five interfaces are interconnected with about the same throughput to Deutsche Telecom; or five interfaces are located at the same spot, so which interface is chosen for latency is irellevant; etc.

### Interface groups at originator
A specific web service (like voice call) might be located deep inside an AS, and hence show different metrics for paths connecting to different border interfaces of that AS (e.g. latency). In the end, however, we only need _one_ (or $N$) optimal path(s) leading to the web service; which outbound interface it passes through is irrellevant, as long as the path quality metric is the best one.

Thus, we allow beacons to be assigned a _group number_, which group them together as a "common optimization goal". Any beacon with the same group number as another may be dropped if the other is better. 

### Interface group at propagator

Ideally, then, we would not only find the optimal paths to all _ASs_, but to all _interfaces_. However, this goal quickly becomes unfeasable, since it would involve an evaluation of the path quality metric from all to all interfaces within an AS. We simplify the algorithm by **grouping similar interfaces together**. "Similar" here describes a set of well-interconnected interfaces that incur little cost in any metric when traffic is routed between them. This could be the case e.g. for all interfaces connecting to the same neighbouring AS at a specific IXP.


### Path Selection Pseudocode

The following algorithm outlines the basic idea of how receveid paths originating at an interface group `o_intfg`, optimizing for a path quality metric `q` are selected s.t. we get the $N$ best paths for every interface group leading to a neighbour `n`. The algorithm is refined to increase performance below:

```python
def get_bcns_to_propagate(o_intfg, n, q):
    """
    o_intf: Origin interface group
    n: neighbour AS
    q: quality paths might optimize for
    """
    bcns_to_propagate = []
    N = 3
    for eg_intfg in "all interface groups leading to neighbour n":
        # Find all path-interface combinations for that group
        all_bcns = []
        for eg_intf in "interface group eg_intfg":
            for bcn in """beacons
                        * originating at o_intfg
                        * optimize for quality q""":
                all_bcns.append(bcn.extend(eg_intf))

        # Select the N best ones i.t.o. their quality q
        all_bcns.sort_by(q)
        bcns_to_propagate += all_bcns.first(N)
    
    return bcns_to_propagte
```

## Implementation
To implement the algorithm into the SCION codebase, the following tasks need to be executed:

- [ ] Interfaces must be configurable to send out these new path-quality-aware beacons for:
    * a defined quality
    * a defined optimization group
    * a defined initial "offset" metric from the end-host to that interface
- [ ] Interfaces must be configurable to be treated as a single group when propagating
- [ ] The **beacon message format** must be adjusted s.t. the optimization goal, the optimization group and the initial metric offset can be placed in the first hop entry of the path construction beacon
- [ ] The metrics along the path that every PCB already travelled must be summarized inside the PCB, so that another AS can evaluate how good this PCB is w.r.t the given metric. For this purpose, the [beacon metadata](https://github.com/Nearoo/scion/blob/master/doc/beacon-metadata.rst) extension is utilized
- [ ] To extend beacons and evaluate different extension options according to the metric, it must be possible to **query the AS topology for the metric values for inter-AS links** as well as **intra-AS ingress-to-egress paths**; and to configure these metrics for the AS. We again use the [beacon metadata](https://github.com/Nearoo/scion/blob/master/doc/beacon-metadata.rst) extension for this purpose
- [ ] The **originator** must be extended to originate these beacons according to the interface configurations
- [ ] The **propagator** / **handler** must be extended to forward received beacons with this extension according to the algorithm outlined above
- [ ] The **beacon store** must be changed to allow query of beacon messages as outlined in the algorithm below, in particular with sub-AS granularity


### Interface Configuration
### PCB Extension at origin
### Integratiom of Beacon Metadata to query AS for path qualities
### Changes to Originator to send new PQA PCBs
### Changes to Propagator to propagate PQA PCBs according to algorithm

To leverage linearity of path metrics as outlines in the introcution, we don't try combining _all_ paths with _all_ interfaces i a given group, but instead query for only the $N$ best paths for every ingress interface:

```python
def get_bcns_to_propagate(o_intfg, n, q):
    """
    o_intf: Origin interface group
    n: neighbour AS
    q: quality paths might optimize for
    """
    bcns_to_propagate = []
    N = 3
    for eg_intfg in "all interface groups leading to neighbour n":
        # Find all path-interface combinations for that group
        all_bcns = []
        for eg_intf in "interface group eg_intfg":
            for ig_intf in "ingress interface":
                # Query for best N with fiven ingress intf
                for bcn in db.query_bcns( origin = o_intfg,
                                        optimizing_for = q
                                        entering_intf = ig_intf,
                                        sort_by = q,
                                        take = N):
                    all_bcns.append(bcn.extend(eg_intf))

        # Select the N best ones i.t.o. their quality q
        all_bcns.sort_by(q)
        bcns_to_propagate += all_bcns.first(N)
    
    return bcns_to_propagte
```
### Changes to Beacon Store to allow for efficient beacon queries


