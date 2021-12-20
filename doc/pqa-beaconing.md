# Push-Based Path Quality Aware Beaconing

This document ountlines the push-based path quality aware beconing algorithm proposed by Seyedali Tabaeiaghdaei and Ahad N. Zehmakan [1], and how it is implemented in the SCION codebase. The pull-based algorithm will be documented later.

* Author(s): Silas Gyger, Seyedali Tabaeiaghdaei
* Status: draft
* Last edited: 2021-12-xx

## Outline
During core beaconing, core ASs continuously have to decide which beacons to forward to which interfaces in order to keep the message complexity sufficiently low. 

Traditional algorithms have focussed on selecting paths with low hop count[2] or high diversity w.r.t. links travelled [3]. The goal of either is to provide each AS with a high quality set of paths to every other AS, such that their target application can (hopefully) select one that suits its needs.

Since service providers know which optimality criteria is required for each type of services (application) they provide, and they have customers all around world in all ISDs (and therefor core ASes), it is reaonable to let origin ASes to specify the optimality criteria of the path originating from them.

### Path metrics

Path metrics are qualities that can be determined of any path between any two nodes, and we expect them to be represented by a unidimensional number. I.e. a metric is a function `m` that takes any path `a ⇝ b` and outputs a float `m(a ⇝ b) : float`.

Given the metric value for path `a ⇝ b` and `b ⇝ c`, we can always determine the metric value for path `a ⇝ b ⇝ c`. There are two ways this can be achieved:
* Additive: `m(a ⇝ b ⇝ c ) = m(a ⇝ b) + m(b ⇝ c)`, e.g, latency, hop count
* Concave: `m(a ⇝ b ⇝ c ) = min/max{m(a ⇝ b), m(b ⇝ c)}`, e.g, throughput
* Multiplicative: `m(a ⇝ b ⇝ c ) = m(a ⇝ b) * m(b ⇝ c)}`, e.g., loss rate

This allows us to break down the problem of finding the best paths into smaller subproblems: For any intermidiary node `b`, _if_ the ideal path travels the node `b`, it can (without worsening the metric) have a subpath that is the ideal path that leads to `b`. Hence, for every node `b`, we only need to consider the (`N`) best path(s) to that node. This fact is exploited in the algorithm to decrease computational overhead.

### Optimality criteria

> TODO: Ok if I put this into bachelor thesis, but not into algorithm?

The optimality criteria is a single path metric (e.g. latency).

### Algorithm granularity

Unlike AS-path length which is linear at the AS-level, other optimality criteria may not be linear at the AS-level, but they are linear at the interface-level. Therefore, selecting the best PCBs to one origin AS and sending them to all egress interfaces may lead to sub-optimal paths and extra messageing overhead. Furthermore, finding the best path to an origin AS is not suffiecient, as different destinations are located in different locations (and my not be necessarily distributed like anycast).

However, optimizaing path per origin interface, and per ingress and egress interface of the propagator AS causes huge overhead. Hence, we propose interface grouping.

### Direction of optimization

The ideal path w.r.t. to a specific quality between two nodes is not necessairly the same in one direction as in the other. As part of the optimization target, we allow ASs to specify in which direction of package transmission the paths should be optmize for. Here, "origin AS" references the AS the beacon originates at, and the "target AS" the AS receiving the beacons. We call the direction of optimization

* **forward**: for packages travelling the _same direction as the beacon_, i.e. origin to target
* **backward**: for packages travelling in the _opposite direction as the beacon_, i.e. target to origin
* **forward and backward**: for packages travelling in _both directions on possibly disjunct paths_
* **bidirectional**: for packages travelling _in both directions on the same path_


### Terms:
* an **optimization interface group** is a set of interfaces `{intf_1, intf_2, ...}` in the origin AS for which an **optimization target** optimizes for (defined below)
* a **direction** describes one of the directions defined above, i.e. `forward`, `backward`, `forward and backward`, or `bidirectional`
* an **optimality criteria** references to one of `latency`, `throughput`, `reliability`.
* an **optimization target** describes a tuple `<origin AS*, uniquifier*, optimality criteria*, direction*>`. The algorithm tries to find `N` ideal paths per optimization target.
    * each **optimization target** maps to a set of interfaces constituting an **optimization interface group**. These interfaces will originate beacons for the given optimization target.
    * the **origin AS** includes the ISD identifier 
    * the **uniquifier** is used to distinguish different optimization targets with identical values but mapping to different optimization interface groups. Uniquifiers can be very short since they only need to distinguish ("uniquify") optimization targets that have otherwise identical fields.

Each **optimization target** represents a "goal" for which `N` ideal paths can be found. An AS can have multiple optimization targets optimizing for the same criterion but associated to different opimization interface groups - the field `uniquifier` can be used to distinguish the two in this case.

Each interface can be configured to originate beacons for none, one or multiple optimization targets. A set of interfaces originating the same optimization target implicitly constitutes an **optimization interface group**. 

### Interface groups in non-origin ASes

In non-origin (propagator) ASes, _interface_groups_ for each optimality criteria can be defined as the group of interfaces from which the intra-AS that criteria has almost the same value to any destination inside that AS (including other interfaces). For example, for latency grouping can be done based on proximity, but for bandwidth all interfaces with the same bandwidth can grouped with each other. Therefore, finding an optimal path from/to an ingress/egress interface in a group (for each optimality criteria) gives almost the same quality when we find an optimal path from/to all of the interfaces in that group. For traffic engineering puposes, ASes can violate this definition, which we do not conside now.

> In some cases neighbor ASes can put the interfaces connected to the same link between them in different groups. In this case thay can communicate their interface groupings, which we do not consider in this project.

### Interface subgroups
Multiple interfaces in the same group can be connected to different ASes. A set of interfaces in the same interface group connected to the same neighboring AS is called an _interface_subgroup_.

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
                propagate_optimized_paths(optim_group, intf_subgroup, neigh)

def propagate_optimized_paths(optim_group, intf_subgroup, neigh):
    # Find N best beacons for every interface group
    
    # First find set of candidates
    intf_beacon_candidates = []
    for egrees_intf in intf_subgroup:
        for ingress_intfg in local_interface_groups[optimality_criteria]:
            # Get the n best paths leading to the ingress interface
            
            # We need to somehow remove loops when accessing the database. The database gives us loop-free paths. Is that possible?
            n_best = db.get_N_best( # of all beacons received
                                    group = optim_group,
                                    ingress_intfg = ingress_intfg,
                                    filter_loops_with = neigh, # Filter loops
                                    )
            for path in n_best:
                # Extend path with hop ingress -> egress interface
                path_extended = path.extend(ingress_intf ⇝ egrees_intf)
                # Add metric of this hop to the path
                if forward:
                    path_extended.extend_metric(ingress_intf ⇝ egress_intf)
                ...
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
There is one special origination target identifier called `NO_TARGET`, which represents a beacong propagated in the usual manner without PQA Beaconing.
#### Option 1: Direction part of optimization target identifier
```yaml
optimization targets:
    my_target_0:
        uniquifier: 0
        quality: latency
        direction: forward
    my_target_1:
        # uniquifier optional, defautls to 0
        quality: latency 
        direction: backward

origination_configuration:
    intf1:
        - [my_target_0, NO_TARGET]
        - [my_target_1]
    intf2: # this is the deafault setting for interfaces not configured at all
        - [NO_TARGET]
```
#### Option 2: Direction not part of optimization target

```yaml
optimization targets:
    my_target_0:
        uniquifier: 0
        quality: latency
    my_target_1:
        # uniquifier optional, defautls to 0
        quality: latency 

origination_configuration:
    intf1:
        - # Interval 0
            -   # Beacon 0
                target: my_target_0
                direction: forward
            -   # Beacon 1
                target: NO_TARGET
        - # Interval 1
            -   # Beacon 0
                target: my_target_1
                direction: bidirectional
    intf2: # this is the deafault setting for interfaces not configured here
        - [NO_TARGET]
```

Note for algorothm:
* If we want N ideal paths _per optimization target and direction_, it's better if we make direction part of optimization group. That's what "optimization target" conceptually should do: Define one goal to optimize for and find N ideal paths.

> Assigning uniquifiers: Unique uniquifiers need to be assigned to two optimization targets exactly if they have otherwise identical fields.


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
