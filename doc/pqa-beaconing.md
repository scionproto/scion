# Push-Based Path Quality Aware Beaconing

This document ountlines the push-based path quality aware beconing algorithm proposed by Seyedali Tabaeiaghdaei and Ahad N. Zehmakan [1], and how it is implemented in the SCION codebase. The pull-based algorithm will be documented later.

* Author(s): Silas Gyger, Seyedali Tabaeiaghdaei
* Status: draft
* Last edited: 2021-12-xx

## Table Of Contents
- [Push-Based Path Quality Aware Beaconing](#push-based-path-quality-aware-beaconing)
  - [Table Of Contents](#table-of-contents)
  - [Algorithm](#algorithm)
    - [Path metrics](#path-metrics)
    - [Algorithm granularity](#algorithm-granularity)
    - [Direction of optimization](#direction-of-optimization)
    - [Optimization Target](#optimization-target)
    - [Interface groups in origin ASes](#interface-groups-in-origin-ases)
    - [Interface groups in non-origin ASes](#interface-groups-in-non-origin-ases)
    - [Interface subgroups](#interface-subgroups)
    - [Path Selection during Propagation](#path-selection-during-propagation)
  - [Implementation](#implementation)
    - [Overview](#overview)
    - [Configuration of PQA algorithm global paramters](#configuration-of-pqa-algorithm-global-paramters)
      - [Modification to codebase](#modification-to-codebase)
      - [Config file specification (yaml):](#config-file-specification-yaml)
    - [Configuration of ASs for PQA beacon origination](#configuration-of-ass-for-pqa-beacon-origination)
      - [Modification to codebase](#modification-to-codebase-1)
      - [Config file specification:](#config-file-specification)
        - [Option 1: Direction part of optimization target identifier](#option-1-direction-part-of-optimization-target-identifier)
        - [Option 2: Direction not part of optimization target](#option-2-direction-not-part-of-optimization-target)
    - [Configuration of interface groups in non-orign ASs](#configuration-of-interface-groups-in-non-orign-ass)
      - [Modification to codebase](#modification-to-codebase-2)
      - [Config File Specification](#config-file-specification-1)
    - [Beacon Messages Modification](#beacon-messages-modification)
      - [New Protobuf Messages](#new-protobuf-messages)
      - [Modifications to codebase](#modifications-to-codebase)
    - [Extend Beacon DB for new queries](#extend-beacon-db-for-new-queries)
    - [Originating new PQA Beacons](#originating-new-pqa-beacons)
    - [Propagate new PQA Beacons](#propagate-new-pqa-beacons)

## Algorithm
During core beaconing, core ASs continuously have to decide which beacons to forward to which interfaces in order to keep the message complexity sufficiently low. 

Traditional algorithms have focussed on selecting paths with low hop count[2] or high diversity w.r.t. links travelled [3]. The goal of either is to provide each AS with a high quality set of paths to every other AS, such that their target application can (hopefully) select one that suits its needs.

Since service providers know which optimality criteria is required for each type of services (application) they provide, and they have customers all around world in all ISDs (and therefor core ASes), it is reaonable to let origin ASes to specify the optimality criteria of the path originating from them.

### Path metrics

Path metrics are qualities that can be determined of any path between any two nodes, and we expect them to be represented by a unidimensional number. I.e. a metric is a function `m` that takes any path `a ⇝ b` and outputs a float `m(a ⇝ b) : float`.

Given the metric value for path `a ⇝ b` and `b ⇝ c`, we can always determine the metric value for path `a ⇝ b ⇝ c`. There are two ways this can be achieved:
* Additive: `m(a ⇝ b ⇝ c ) = m(a ⇝ b) + m(b ⇝ c)`, e.g, latency, hop count
* Concave: `m(a ⇝ b ⇝ c ) = min/max{m(a ⇝ b), m(b ⇝ c)}`, e.g, throughput
* Multiplicative: `m(a ⇝ b ⇝ c ) = m(a ⇝ b) * m(b ⇝ c)}`, e.g., loss rate

Optimization is done w.r.t. to a single quality, i.e. it is maximized or minimized for a specific quality.

The algorithm will allow optimization of the following metrics:

Quality | Combination | Optimization
--- | ---- |---
latency | additive | min
throughput | concave (min) | max
loss rate | multiplicative | min

### Algorithm granularity

Unlike AS-path length which is linear at the AS-level, other optimality criteria may not be linear at the AS-level, but they are linear at the interface-level. Therefore, selecting the best PCBs to one origin AS and sending them to all egress interfaces may lead to sub-optimal paths and extra messageing overhead. Furthermore, finding the best path to an origin AS is not suffiecient, as different destinations are located in different locations (and my not be necessarily distributed like anycast).

However, optimizaing path per origin interface, and per ingress and egress interface of the propagator AS causes huge overhead. Hence, we propose interface grouping.

### Direction of optimization

We allows to be optimized for packets travelling in the same direction as the beacon ("**forward**"), in opposite direction ("**backwards**"), and in both directions on the same path ("**bidirectional**"). 

How optimal forward paths are communicated back to the originator is not part of this project.

### Optimization Target

An optimization target is the tuple `<origin AS*, uniquifier*, optimization quality*, optimization direction*>`. The algorithm attempts to find up to `N` ideal paths per optimization target. The fields are defined as follows:

* `origin AS` gloablly identifies the AS
* `uniquifier` is a small number used to distinguish different optimization targets with otherwise identical fields
* `optimality criteria` is an identifier representign the path quality to optimize for, i.e. one of `throughput`, `latency` and `loss rate`
* `optimization direction` is one of `forward`, `barckward` and `bidirectional`, as explained above

### Interface groups in origin ASes

Multiple interfaces can originate the same optimization target; a group of interfaces originating the same target consitutes an `optimization interface group`. 

Interfaces can be configured to originate none, one or multiple in one or multiple different origination intervals. Optimization interface groups are created implicitly by assigning interfaces to optimization targets. 

### Interface groups in non-origin ASes

In non-origin (propagator) ASes, _interface_groups_ for each optimality criteria can be defined as the group of interfaces from which the intra-AS that criteria has almost the same value to any destination inside that AS (including other interfaces). For example, for latency grouping can be done based on proximity, but for bandwidth all interfaces with the same bandwidth can grouped with each other. Therefore, finding an optimal path from/to an ingress/egress interface in a group (for each optimality criteria) gives almost the same quality when we find an optimal path from/to all of the interfaces in that group. For traffic engineering puposes, ASes can violate this definition, which we do not conside now.

> In some cases neighbor ASes can put the interfaces connected to the same link between them in different groups. In this case thay can communicate their interface groupings, which we do not consider in this project.

### Interface subgroups
Multiple interfaces in the same group can be connected to different ASes. A set of interfaces in the same interface group connected to the same neighboring AS is called an _interface_subgroup_.

### Path Selection during Propagation

For every origin optimization target `optim_target` for which we receive beacons, we execute the beacon selection algorithm for every neighbour as `neigh`. 

```python
def run():
    # Retreive all optimization groups for which we have beacons

    # optim_target = <origin AS, uniquifier, optimality criteria, direction>
    optim_targets = db.get_optim_targets_from_received_beacons()
    # Run algorithm for each optimization group & neighbouring AS:
    for optim_target in optim_targets:
        for neigh in neighbouring_ASs:
            for intf_group in local_interface_groups[optimality_criteria]:
                intf_subgroup = intf_group.filter_leading_to(neigh)
                propagate_optimized_paths(optim_target, intf_subgroup, neigh)

def propagate_optimized_paths(optim_target, intf_subgroup, neigh):
    # Find N best beacons for every interface group

    # First find set of candidates
    intf_beacon_candidates = []
    for egrees_intf in intf_subgroup:
        for ingress_intfg in local_interface_groups[optimality_criteria]:
            # Get the n best paths leading to the ingress interface
            
            # Return the N best paths for given criterion of all beacons received.
            n_best = db.get_N_best(
                                    target = optim_target, # optimization target
                                    ingress_intfg = ingress_intfg, # leading through ingress interface groups
                                    exclude_looping_with = neigh, # Filter out loops
                                    )
            for path in n_best:
                # Extend path with hop ingress -> egress interface
                path_extended = path.extend(ingress_intf ⇝ egrees_intf)
                # Add metric of this hop to the path
                if "forward" in optim_target.direction:
                    path_extended.extend_metric(ingress_intf ⇝ egress_intf, optim_target.quality)
                if "backward" in optim_target.direction:
                    path_extended.extend_metric(egress_intf ⇝ ingress_intf), optim_target.quality)
                if "bidirectional" in optim_target.direction:
                    path_extended.extend_metric_bidirectional(egress_intf, ingress_intf, optim_target.quality)
                # Add the metric of the inter-AS link at the egress interface
                path_extended.extend_metric(egress_intf.link)

                intf_beacon_candidates.append(path_extended)

    # Chose & propagate the n best ones
    n_best = get_N_best(intf_beacon_candidates)
    propagate(n_best)
```

## Implementation
### Overview
To implement the algorithm into the SCION codebase, the following tasks need to be executed:

- [ ] Configuration of PQA algorithm global paramters, such as:
    * Possible quality metrics, and their mode of combination
    * `N`
- [ ] Configuration of ASs for PQA beacon origination
    * define optimization targets
    * configure interfaces to originate beacons for optimization targets and/or normal beacons
- [ ] Configuration of AS for PQA beacon propagation
    * define interface groups
- [ ] Add beacon segment messages extension for PQA beacons, must include:
    * uniquifier
    * optimization quality
    * optimization direction
- [ ] Allow queries of the form outlined in the pseudocode to the db, i.e. get arrived beacons for:
    * a given **optimization target** in the beacon
    * a given **ingress interface group** through which the beacon entered the AS
    * a given **neighbouring AS** for which looping beacons should be ignored
- [ ] Make the AS originate PQA beacons according to the configuration
- [ ] Make the AS propagate PQA beacons according to the configuration

### Configuration of PQA algorithm global paramters

#### Modification to codebase
Definition, loading etc. is done analogously to `StaticConfig` extension, e.g.:
* config defined and loaded in `../go/cs/beaconing/pqa_config.go`
* config file path resgtered in `../go/lib/env.go` etc.

#### Config file specification (yaml):

```yaml
General:
    No Beacons Per Quality: 5

Qualities:
    latency:
        short: lt
        combination: additive
        optimality: min
        symmetry_tolerance: 0.1
        proto_pqa_id: LATENCY
    throughpput:
        sshort: tp
        combination: concave-min
        optimality: max
        proto_id: THROUGHPUT
    loss-rate:
        short: lr
        combination: multiplicative
        optimality: min
        proto_id: LOSSRATE
    foo-bar:
        short: fb
        combination: concave-max
        optimality: max
```

> Question: Good idea to add mapping to protobuf into config file?
> Other things that need to be done are:
> * mapping to StaticInfoExtension quality
> Perhaps better to add this info 

Explaination:
* `General`:
  * `No Beacons Per Quality`: Parameter `N` in this document
* `Qualities`:
  * [`global quality identifier`]:
    * `short`: ... what's put into the beacon?
    * `combination`: one of `additive`, `multiplicative`, `concave-min`, `concave-max`.
    * optimality: `min` or `max`
    * `symmetry_tolerance`: tolerance to consider two metrics "the same" when optimizing for symmetric, as a fraction (`a == b <=> [a*(1-tol), a*(1+tol)] ∩ [b*(1-tol), b*(1+tol)] != ∅`)
    * `proto_id`: The string representation of the field value of `OptimizationQuality` in the protobuf segment extension

> TODO: Add connection to beacon metadata exteion
> TODO: Make sure contained fields can be transferred into beacon
> TODO: Make sure everything is there

###  Configuration of ASs for PQA beacon origination

#### Modification to codebase
* Definition, loading etc. is is done analogously to `StaticConfig` extension, e.g.:
  * The struct describing the interface configuration is located in a new directory in [lib/ctr/seg/extensions](../go/lib/ctrl/seg/extensions). The directory contains a file for the extension 
  * The extension is registered at [lib/ctrl/seg/extensions.go](../go/lib/ctrl/seg/extensions.go#L23)itself, and a file testing the extension. 
  * The configuration is read in a file calld `pqa_origination_config.go` located at [../go/cs/beaconing](../go/cs/beaconing).

#### Config file specification:
##### Option 1: Direction part of optimization target identifier
```yaml
optimization targets:
    my_target_0:
        uniquifier: 0
        quality: latency
        direction: forward
    my_target_1:
        # uniquifier optional, found automatically if left out
        quality: latency 
        direction: backward

origination_configuration:
    intf1:
        - [my_target_0, NO_TARGET]
        - [my_target_1]
    intf2: # this is the deafault setting for interfaces not configured at all
        - [NO_TARGET]
```

Explaination:
* `optimization_targets`:
  * [optimization_target_identifier] only used internally
    * `uniquifier`: Optional, assigned automatically. Can be defined to keep temporaly consistency across config rewrites
    * `quality`: references a quality defined in the global config file
    * `direction`: one of: `forward`, `backward`, `bidirectional`, or a combination of them separated by spaces (e.g. `forward backward`)
* `origination_configuration`:
  * [interface identifier]:
    * List of origination intervalls:
      * interval configuration. Each element is an `optimization_target_identifier` or `NO_TARGET`. All optimization targets (incl.. `NO_TARGET`) are sent out at once during this interval. `NO_TARGET` references beacons without the extenion.

If an interface is not configured at all, it is assumed to only originate `NO_TARGET` beacons.
##### Option 2: Direction not part of optimization target

```yaml
optimization targets:
    my_target_0:
        uniquifier: 0
        quality: latency
    my_target_1:
        uniquifier: 1
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


### Configuration of interface groups in non-orign ASs

#### Modification to codebase
> TODO: Think this through

* Definition, loading etc. is is done analogously to `StaticConfig` extension, e.g.:
  * The struct describing the interface configuration is located in a new directory in [lib/ctr/seg/extensions](../go/lib/ctrl/seg/extensions). The directory contains a file for the extension 
  * The extension is registered at [lib/ctrl/seg/extensions.go](../go/lib/ctrl/seg/extensions.go#L23) itself, and a file testing the extension. 
  * The configuration is read in a file calld `pqa_origination_config.go` located at [../go/cs/beaconing](../go/cs/beaconing).


Each interface group has a set of interfaces plus a set of optimization target criterions associated with it. If an optimization target fits a criterion, it will be returned in the `local_interface_groups[optimality_criteria]` line in the pseudocode.

For a given optimality criterion, if an interface is not part of any group, it is treated as though it had it's own group with a single member.

An optimization target criterion is either both the path quality and optimization direction, or just the path quality.


#### Config File Specification
```yaml
interface_group_foo:
    interfaces:
        - intf1
        - intf2
        - intf3
    optimization targets:
        -
            quality: latency
        -
            quality: throughput
            direction: forward
```

Explaination:
* [`interface group identifier`]:
  * `interfaces`:
    * a list of interface identifiers that are part of this group
  * `optimization targets`:
    * a list of optimization targets criterions. Each element contains:
      * `quality`: the optimization quality identifier from the global config file
      * `direction` (optional): one or more directions for the optimization target

### Beacon Messages Modification
> Q: Each beacon needs info on optimization only _once_ - is "segment" right place to put it?

#### New Protobuf Messages

```protobuf
message PQABExtension {
    // Is contained in first segment, but not in others
    optional OptimizationTarget target = 1;
}


message OPtimizationTarget {
    // Source AS is implicit through beacon origin
    OptimizationQuality quality = 1;
    OptimizationDirection direction = 2;
    uint8 uniquifier = 3;
}

enum OptimizationQuality {
    LATENCY = 1;
    BANDWITH = 2;
    LOSSRATE = 3;
}

enum OptimizationDirection {
    FORWARD = 1;
    BACKWARD = 2;
    FORWARD_BACKWARD = 3;
    SYMMETRIC = 4;
}

```
#### Modifications to codebase
* register extension in struct in [extensions.go](../go/lib/ctrl/seg/extensions.go)


### Extend Beacon DB for new queries

* New Query Params need to be added to [`type QueryParams struct` in storage/beacon/beacon.go](../go/pkg/storage/beacon/beacon.go#36)
* The schema needs to be extended with fields:
  * optimization quality
  * optimization direction
  * optimization uniquifier
* Extend [`storage/beacon/sqlite/db.go`](../go/pkg/storage/beacon/sqlite/db.go) with methods to query the db according to the pseudocode; modify `InsertBeacon()` for new schema
* Add same interfaces to [`store.go](../go/cs/beacon/store.go), so that they can be used by propagator

### Originating new PQA Beacons
> Q: Is this the right approach? 

* Since new beacons call `Extender.Extend` on new beacon in [originator.go/createBeacon](../go/cs/beaconing/originator.go#L202), we add info of extension to (`DefaultExtender.Extend`)[../go/cs/beaconing/extender.go], again with a similar approach to the static info extension (good idea?) possibly with a new field `PQABeaconingExtension` or similar.

### Propagate new PQA Beacons

In [`propagator.go`](../go/cs/beaconing/propagator.go), the propagation algorithm is performed on the beacons according to the algorithm described, using the configuration described and querying the database as described, possibly refactoring existing code.

**Note:** The algorithm is implemented s.t. the old algorithm still takes care of "normal" beacons. The existing code is refactored and changed s.t. at some point, an if-else switch propagates beacons by the old or by the new algorithm, depending on wether the beacon contains the extension.

