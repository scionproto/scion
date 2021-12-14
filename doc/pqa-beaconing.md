# Push-Based Path Quality Aware Beaconing

This document ountlines the push-based path quality aware beconing algorithm proposed by Seyedali Tabaeiaghdaei and Ahad N. Zehmakan [1], and how it is implemented in the SCION codebase. The pull-based algorithm will be documented later.

* Author(s): Silas Gyger, Seyedali Tabaeiaghdaei
* Status: draft
* Last edited: 2021-12-xx

## Outline
During core beaconing, core ASs continuously have to decide which beacons to forward to which interfaces in order to keep the message complexity sufficiently low. 

Traditional algorithms have focussed on selecting paths with low hop count[2] or high diversity w.r.t. links travelled [3]. The goal of either is to provide each AS with a high quality set of paths to every other AS, such that their target application can (hopefully) select one that suits its needs.

Since service providers know which optimality criteria is required for each type of services (application) they provide, and they have customers all around world in all ISDs (and therefor core ASes), it is reaonable to let origin ASes to specify the optimality criteria of the path originating from them.

## Considerations

The final algorithm is the result of a set of considerations of the problem at hand.

### Path metrics

Path metrics are qualities that can be determined of any path between any two nodes, and we expect them to be represented by a unidimensional number. I.e. a metric is a function `m` that takes any path `a ⇝ b` and outputs a float `m(a ⇝ b) : float`.

Given the metric value for path `a ⇝ b` and `b ⇝ c`, we can always determine the metric value for path `a ⇝ b ⇝ c`. There are two ways this can be achieved:
* Additive: `m(a ⇝ b ⇝ c ) = m(a ⇝ b) + m(b ⇝ c)`, e.g, latency, hop count
* Concave: `m(a ⇝ b ⇝ c ) = min/max{m(a ⇝ b), m(b ⇝ c)}`, e.g, throughput
* Multiplicative: `m(a ⇝ b ⇝ c ) = m(a ⇝ b) * m(b ⇝ c)}`, e.g., loss rate

This allows us to break down the problem of finding the best paths into smaller subproblems: For any intermidiary node `b`, _if_ the ideal path travels the node `b`, it can (without worsening the metric) have a subpath that is the ideal path that leads to `b`. Hence, for every node `b`, we only need to consider the (`N`) best path(s) to that node. This fact is exploited in the algorithm to decrease computational overhead.

### Optimality criteria

The optimality criteria can be a single path metric (e.g, latency), or a small objctive function to combine different metrics such as latency and bandwidth.

### Algorithm granularity

Unlike AS-path length which is linear at the AS-level, other optimality criteria may not be linear at the AS-level, but they are linear at the interface-level. Therefore, selecting the best PCBs to one origin AS and sending them to all egress interfaces may lead to sub-optimal paths and extra messageing overhead. Furthermore, finding the best path to an origin AS is not suffiecient, as different destinations are located in different locations (and my not be necessarily distributed like anycast).

However, optimizaing path per origin interface, and per ingress and egress interface of the propagator AS causes huge overhead. Hence, we propose interface grouping, which is not necessarily based on geographical proximity. Below, we explain more.

### Interface groups in origin ASes

For each optimality criteria, the origin AS groups its interfaces together in _origin_interface_group_ s. For different criteria, the grouping can be done in differnet manners. Grouping is not necessarily based on geographical proximity. 

When initiating beaconing process, each origin AS specifies the optimality criteria  and the _origin_interface_group_ of the egress interface in PCBs; one PCB per optimality criteria is sent out from each interface. 

### Optimization groups

We define the _optimization_group_ as the `<origin AS, origin interface group, optimality criteria>` tuple.

### Interface groups in non-origin ASes

In non-origin (propagator) ASes, _interface_groups_ for each optimality criteria can be defined as the group of interfaces from which the intra-AS that criteria has almost the same value to any destination inside that AS (including other interfaces). For example, for latency grouping can be done based on proximity, but for bandwidth all interfaces with the same bandwidth can grouped with each other. Therefore, finding an optimal path from/to an ingress/egress interface in a group (for each optimality criteria) gives almost the same quality when we find an optimal path from/to all of the interfaces in that group. For traffic engineering puposes, ASes can violate this definition, which we do not conside now.

In some cases neighbor ASes can put the interfaces connected to the same link between them in different groups. In this case thay can communicate their interface groupings, which we do not consider in this project.

### Interface subgroups
Multiple interfaces in the same group can be connected to different ASes. A set of interfaces in the same interface group connected to the same neighboring AS is called an _interface_subgroup.

### Path Selection during Propagation

For every origin optimization group `optim_group` for which we receive beacon, we execute the beacon selection algorithm for every neighbour as `neigh`. 

```python
def run():
    # Retreive all optimization groups for which have beacons
    # optim_groups = <origin AS, origin interface group, optimality criteria>
    optim_groups = db.get_optim_groups_from_received_beacons()
    # Run algorithm for each optimization group & neighbouring AS:
    for optim_group in optim_groups:
        for neigh in neighbouring_ASs:
            for intf_subgroup in local_interface_groups[optimality_criteria][neigh]:
                propagate_optimized_paths(optim_group, intf_subgroup)

def propagate_optimized_paths(optim_group, intf_subgroup):
    # Find N best beacons for every interface group
    
    # First find set of candidates
    intf_beacon_candidates = []
    for egrees_intf in intf_subgroup:
        for ingress_intfg in local_interface_groups[optimality_criteria]:
            # Get the n best paths leading to the ingress interface
            
            # We need to somehow remove loops when accessing the database. The database gives us loop-free paths. Is that possible?
            n_best = db.get_N_best( # of all beacons received
                                    group = optim_group,
                                    ingress_intfg = ingress_intfg
                                    )
            for path in n_best:
                # Extend path with hop ingress -> egress interface
                path_extended = path.extend(ingress_intf ⇝ egrees_intf)
                # Add metric of this hop to the path
                path_extended.extend_metric(ingress_intf ⇝ egress_intf)
                # Add the metric of the inter-AS link at the egress interface
                path_extended.extend_metric(egress_intf.link)

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
