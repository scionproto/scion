# Path Quality Aware Beaconing

This document ountlines the path quality aware beconing algorithm proposed by Ali and Adrian [1], and how it is implemented in the SCION codebase. 

* Author(s): Silas Gyger
* Status: draft
* Last edited: 2021-12-xx

## Outline
During core beaconing, core ASs continuously have to decide which beacons to forward to which interfaces in order to keep the message complexity sufficiently low. 

Traditional algorithms have focussed on selecting paths with low hop count[2] or high diversity w.r.t. links travelled [3]. The goal of either is to provide each AS with a high quality set of paths to every other AS, such that their target application can (hopefully) select one that suits its needs.

In certain situations, it's already known which path qualities end hosts will be looking for when they connect to a specific interface. For instance, a internet video call service provider will already know that all of its customers will be looking for low-latency connections to its video call endpoint. Offering a selection of paths with varying qualities in this case is an uncessary overhead. The following document outlines a mechanism wich allows core ASs to define qualities for beacons originating from defined applications for which the beaconing process should optimize for; the end result of the beaconing process should be that all parties will end up with paths that are optimal with respect to this quality to that target application, and have diversity at most in other qualities.

## Considerations

The final algorithm is the result of a set of considerations of the problem at hand.

### Path granularity

Unlike in previous algorithms, AS-level granularity becomes insufficent to determine the quality of a path with respect to many metrics. For instance, a path optimized for latency will have different quality metric in this respect when forwarded to the same neighbouring AS in Munich as opposed to Sidney. However, both Sidney and Munich might benefit from receiving the beacons, as they might still contain the fastest route to either place. 

### Path metrics

Path metrics are qualities that can be determined of any path between any two nodes, and we expect them to be represented by a unidimensiona number. I.e. a metric is a function `m` that takes any path `a ⇝ b` and outputs a float `m(a ⇝ b) : float`.

Given the metric value for path `a ⇝ b` and `b ⇝ c`, we can always determine the metric value for path `a ⇝ b ⇝ c`. There are two ways this can be achieved:
* A: `m(a ⇝ b ⇝ c ) = m(a ⇝ b) + m(b ⇝ c)`, example: latency, hop count
* B: `m(a ⇝ b ⇝ c ) = min/max{m(a ⇝ b), m(b ⇝ c)}`, example: throughput, link trustworthyness

This allows us to break down the problem of finding the best paths into smaller subproblems: For any intermidiary node `b`, _if_ the ideal path travels the node `b`, it can (without worsening the metric) have a subpath that is the ideal path that leads to `b`. Hence, for every node `b`, we only need to consider the (`N`) best path(s) to that node. This fact is exploited in the algorithm to decrease computational overhead.

### Grouping Interfaces During Origination

Ideally, we'd like to have ideal paths to every single target _service_ (like e.g. Skype) and consider in the optimization process the quality cost incurred even within the origin AS, between service end hosts and egress interface. However, creating a new optimization goal for every single application is obviously unfeasable. The algorithm simplifies this problem by allowing beacon originating ASs to _group interfaces_ together, but not include any intra-AS metric offsets. Instead of finding the ideal path (wrt. a certain quality) to each application, the ideal path to each defined group is found. Skype can optimize connection to these interfaces internally on its own; the cost incurred on the path from Skype's server these groups is not considered in the algorithm.

We call these groups of interface groups **optimization groups**, because at the end of the algorithm one (or `N`) optimal path is found per group. An optimization group **includes the identifier of the AS** as well as **the quality it optimizes for**. Every group optimizes for exactly one quality. 

### Grouping Interfaces During Propagation

During propagation of paths to a neighbour AS, we'd like to send that AS the ideal path to each interface connecting us to that AS: internally, the path metrics might differ substancially between ingress-interfaces for specific end-hosts or egress interfaces leading to the next neighbouring ASs.

It is however often the case that multiple interfaces are located in close proximity and are well connected, in that travelling from one interface to the other incurs litle cost in any metric. Finding an optimal path to one of these interfaces is equivalent to finding an optimal path to all of the interfaces. Thus, we'd like to let ASs define groupings of interfaces that can be considered as a unit during optimization, and communicate those to their neighbours. For instance, if AS "A" has a set of interfaces that are well enmeshed on it's side s.t. all metrics from any node incur basically the same cost to any of the interface, we'd like as "A" to be able to communicate that to the AS at the other end of the links; that other AS then only has to find `N` optimal paths to _any_ of those interfaces. 

Communicating groups to neighbours is considered **out of scope** of this project. We do let ASs define interface groups that are well connected; however, we also let ASs define groups of interfaces that are well connected on the side of the neighbour, as though these groups were communicated by the neighbour. At a later stage, those second groups would be superfluous, as they're the first group communicated by the neighbour.

We call groups that are well connected to be **mesh groups** and groups that "simulate" the mesh groups of the neighbours **neighbour mesh groups**. They're expected to have littler overlap; the algorithm assumes that neighbour-mesh-groups are not well interconnected, and moving from one interface to another can incur significant cost. 

### Path Selection during Propagation

For every origin optimization group `optim_group` for which we receive beacon, we execute the beacon selection algorithm for every neighbour as `neigh`. 

```python
def run():
    # Retreive all optimization groups for which have beacons
    optim_groups = db.get_optim_groups_from_received_beacons()
    # Run algorithm for each optimization group & neighbouring AS:
    for optim_group in optim_groups:
        for neigh in neighbouring_ASs:
            run_algorithm(optim_group, neigh)

def run_algorithm(optim_group, neigh):
    # Find N best beacons for every interface group
    for interface_group leading to neigh:
        # First find set of candidates
        intf_beacon_candidates = []
        for interface egrees_intf in interface_group:
            for interface group ingress_intfg leadining into this AS:
                # Get the n best paths leading to the ingress interface
                n_best = db.get_N_best( # of all beacons received
                                    group = optim_group,
                                    ingress_intfg = ingress_intfg
                                    )
                for path in n_best:
                    # Extend path with hop ingress -> egress interface
                    path_extended = path.extend(ingress_intf ⇝ egrees_intf)
                    # Add metric of this hop to the path
                    path_extended.add_metric(ingress_intf ⇝ egress_intf)
                    # Add the metric of the inter-AS link at the egress interface
                    path_extended.add_metric(egress_intf.link)

                    intf_beacon_candidates.append(path_extended)

        # Remove becaons that would create a loop
        no_loop = remove_looping(intf_beacon_candidates)
        # Chose & propagate the n best ones of the remaining
        n_best = get_N_best(no_loop)
        propagate(n_best)
```

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


- [ ] Interfaces of origin ASs must be configurable to send out new path-quality-aware becons, for configurable:
    * quality to optimize for
    * optimization group the interface is part of

    While still allowing for "normal" beacons to be sent out; how often which beacons are sent out must be part of the configuration.
- [ ] Interfaces of propagator ASs must be configurable to be treated as a single group when propagating
- [ ] The **beacon message format** must be adjusted s.t.  
     * the optimization quality
     * the optimization group

    Can be written iside the first hop fiel (Q1).
- [ ] The metrics along the path that every PCB already travelled must be summarized inside the PCB, so that another AS can evaluate how good this PCB is w.r.t the given metric. For this purpose, the [beacon metadata](https://github.com/Nearoo/scion/blob/master/doc/beacon-metadata.rst) extension is utilized
- [ ] To extend beacons and evaluate different extension options according to the metric, it must be possible to **query the AS topology for the metric values for inter-AS links** as well as **intra-AS ingress-to-egress paths**; and to configure these metrics for the AS. We again use the [beacon metadata](https://github.com/Nearoo/scion/blob/master/doc/beacon-metadata.rst) extension for this purpose
- [ ] The **originator** must be extended to originate these beacons according to the interface configurations
- [ ] The **propagator** / **handler** must be extended to forward received beacons with this extension according to the algorithm outlined below
- [ ] The **beacon store** must be changed to allow query of beacon messages as outlined in the algorithm below, in particular with sub-AS granularity

### Origin Interface Configuration
Design goals:
* Each interface should be configurable to send out beacons for both path-quality-aware beaconing and default beaconing, or a combination of the two
* Configuration should be backwards compatible in that current configuration results in purely default beaconing

Design:
Interface configuration for this purpose is treated as an extension called "PQA Origination"

* The struct describing the interface configuration is located in a new directory in [lib/ctr/seg/extensions](../go/lib/ctrl/seg/extensions). The directory contains a file for the extension itself, and a file testing the extension. The extension itself contains:
    * A struct moddeling the data of the extension
    * the metho `FromPB` extracting the data from a protobuf representation (why? which protobuf?)
    * the method `ToPB` putting the data into a protobuf representation (why? which protobuf?)
* The extension is registered at [lib/ctrl/seg/extensions.go](../go/lib/ctrl/seg/extensions.go#L23)
    * The extension is registered in the `Extensions` struct
    * The from/toPB above are added to the `extensionsFrom/ToPB` methods
* Configuration is part of a new file called `optimizationGroupConfig.json`. It's parsed in the file `optimization_group.go` located at [../go/cs/beaconing](../go/cs/beaconing).
    * It contains:
        * Methods to marshal & unmarshal config files
        * Methods to validate config files
        * Methods to generate new config files
    * The struct implements the interfaces defined at [config.go](../go/lib/config/confi.go), implementing methods to:
        * Initialize
        * Validate
        * Sample generate
    * The location of the json file is registered in [env.go](../go/lib/env/env.go) as a field `OptimizationGroupExtensionConf`

    ### Config File specification:
    Groups are created by extending the `groups` map. A group is identified by the key of the map; the value is the quality it optimizes.
    ```json
    "groups": {
                "latency_#1": "latency",
                "throughput_#3": "throughput",   // TODO: Use keys from static info extension
            }
    ```
    Interfaces are configured to send beacons of different groups in different intervals. The field `bcn` contains the order of beacons. It's a list in which each element represents the configuration for a single interval. After all beacons we sent out for all intervals, we cycle back to the first element. 

    Each interval configuration is a list of optimization group identifiers. The identifier `NO_PQA` is special: It sends out a "normal" beacon without the PQA Extension. All others identify groups defined in the `"groups"` map above. Example:

    ```json
        "interfaces": {
            "22": {
                "bcns": [
                ["NO_PQA"],
                ["NO_PQA", "latency_#1"], 
                    ]
                }
            }
        }
    ```

    This configuration file contains three beaconing interval configuration for the interface "22":
    * In the first beaconing interval, a single normal beacon is sent out.
    * In the second interval, a normal beacon as well as a beacon for the optimization group `"latency_#1"` is sent out
    * In the third interval, we start over and send again a single normal beacon, and o so on

### Propagator Interface Configuration
### Protobuf Segment Extension

We add the `PQABeaconingExtension` to segment info. The info contains:
* The optimization group
* the optimization goal

The extension is inserted into `PathSegmentExtensions`at [seg_extensions.proto](../proto/control_plane/v1/seg_extensions.proto#L23).

> This data should only be included once per beacon. How?

A new message is created called `PQABeaconingExtension`:

```proto
message PQABeaconingExtension {
    string PQAOptimizationGroup = 1;
    PQAOptimizationMetric metric = 2;
}

enum PQAOptimizationMetric {
    METRIC_LATENCY = 1;
    METRIC_BANDWITH = 2;
}

```


### Integratiom of Beacon Metadata to query AS for path qualities

New Function in `/go/cs/.../`
```go
func (AS* a) getMetricValueForIntraASPath(ingress_intf, egress_intf) quality float {};
```

Calling:
* `go/cs/...` for metric xyz

### Changes to originate new PQA Beacons
> Q: How to only add info in the first hop?

* Changes to [extender.go](../go/cs/beaconing/extender.go):
    * Add PQABeaconingInfo as a function to the `DefaultExtended` ([link]([extender.go](../go/cs/beaconing/extender.go#L44)))
    * Fill `asEntry.Extensions.PQABeaconing` in `Extend` (Line 66)
    * Parse `pqaConfig` in [main.go](../go/cs/main.go#L592) and pass to [`TaskConfig`](../go/cs/main.go#615)
    * Pass this data from `TaskConfig`  to the `DefaultExtender` at [`tasks.go`](../go/pkg/cs/tasks.go#L200)
    * **If next AS entry is first AS entry, add this info**

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

The runtime algorithm becomes with:
* the number of ingress interfaces $i_{in}$
* the maximum number of beacons per ingress interface $b_i$
* the number of interface groups $g$ 
* the number of egress interfaces per group $i_{out}^g$
* the number of beacons we want to optimize for $N_b$

The runtime overall becomes 
### Changes to Beacon Store to allow for efficient beacon queries

```go
func (Store* store) query_bcns(origin,
                                optimizing_for,
                                entering_intf,
                                sort_by_quality,
                                take=N) bcn[] {}
```


### Questions:

1: I need to extend the beacon info for the _entire beacon_, not for each hop. Do I put this simpliy into the first hop field?