# Embedding Static Information in SCION Beacons

In order to estimate certain properties of a SCION path segment, static
information about that path can be embedded inside the path construction beacons
in the form of an extension.

## Table of Contents

- [Static Properties](#static-properties)
- [Latency Information](#latency-information)
- [Geographic Information](#geographic-information)
- [Link Type](#link-type)
- [Maximum Bandwidth](#maximum-bandwidth)
- [Number of Internal Hops](#number-of-internal-hops)
- [Note](#note)
- [Concrete Format Extension](#concrete-format-extension)
- [Config File Format](#config-file-format)
- [Command Line Interface](#command-line-interface)

## Static Properties

A static property is any quantifiable piece of information describing a
property of a SCION path segment that remains unchanged over the entire
duration of the lifetime of that path segment.

The following assumptions are made:

- The Beacon Service, which is responsible for adding all this metadata, has
  reliable information about the infrastructure (such as the border routers
  and the interfaces attached to them)
- The AS topology remains stable throughout the lifetime of a path segment

### Inter- vs Intra-AS Metrics
The diagram below illustrates the difference between inter- and intra-as 
metrics.

![Inter VS Intra Metrics](fig/inter_vs_intra_metrics.png)

In order to be able to calculate e.g. the end-to-end
propagation delay of a path starting in AS 2 and ending in AS 3, we need
both the delay inside each AS (intra-AS), as well as the delay on the
connections between ASes (inter-AS). 

#### Intra-AS Metrics

When measuring intra-AS metrics,
the egress interface is the "target" interface, to which the metric is
measured from every other interface. Only having the
metric between the ingress and egress interface is not sufficient 
(see below).

#### Inter-AS Metrics

The PCB is extended with metrics describing the outgoing connection (i.e. the 
child link). Looking at the figure
above, this means that AS 1 extends the PCB with information about its child link
from interface 2 to 3 before propagating it to AS 2.
This assures that:

- The PCB always carries information about the entire path
it has traversed so far

Using this method, end-to-end metrics can be calculated by simply combining
intra- and inter-AS metrics.

## Path Segment Combination

### Segments

As the structure of an AS Entry is identical for up- and down segments,
both of them are extended in the same way.
AS Entries in core segments are treated slightly differently in that all
entries related to peering and shortcuts are omitted (see individual properties
for details).
Since each AS Entry carries information about one AS on the path, the different
segments of a path can be combined as follows: 

- Create an initially empty list of extension entries
- Look at each segment in order
- Extract the extension information from each AS Entry of the current segment
  and add it to the list
- The resulting list of extension entries contains all the information
  necessary to calculate metrics for the end-to-end path

### Normal Path

![Normal Path](fig/normal_paths_with_labels.png)

In the case of a "normal" path without shortcuts or peering links, the
interfaces where traffic enters and leaves correspond to the ingress and
egress interfaces saved in the AS Entry of the PCB. The terms ingress and
egress interface refer to the way these interfaces would be encoded in the
PCB during the beaconing process.
Therefore the lower interface is always labelled as the egress interface, even when it is in
the up segment and would thus technically be the interface on which traffic enters the AS.
Calculating end-to-end metrics can therefore be done by simply adding up the intra-AS
latency (from ingress to egress interface) as well as the inter-AS latency (from egress
interface to the next AS on the path) for every AS on the end to end path.

### Shortcuts

![Shortcut Path](fig/shortcut_paths_with_labels.png)

In the diagram above, traffic will enter AS 2 via interface 22.
Traffic will leave AS 2 via interface 23. Information about the
metrics of the child link attached to interface 22 is included in the up segment.
Metrics describing the intra-AS connection between interface 22 and 23 are also
included in the up segment, in the AS Entry of AS 2. Metrics describing the
child link attached to interface 23 are included in the down segment.
Thus the total of all extensions of the path segments thus contains information about
both the inter-AS connection between AS 3 and AS 2, and the inter-AS connection
between AS 2 and AS 4.

To deal with shortcut connections it is therefore sufficient to encode the following
2 things: 

- The intra-AS metrics from the egress interface to every other interface in the AS
- The inter-As metrics of the child link

### Peering Links

![Peering Path](fig/peering_paths_with_labels.png)

As the figure shows, peering interfaces may differ from the egress interface encoded
in the AS Entry. Therefore, in addition to the list above, we also need to store the
inter-AS metrics for every connection attached to a peering interface of the AS in
the extension.

### Symmetry

In order to reduce the amount of data we need to include in the PCBs in total,
it is assumed that intra-AS metrics are symmetric. We can illustrate the use of
this assumption using the drawing of a shortcut path above.

In the PCB sent to AS 3,
the metric between interface 22 (the egress interface for this PCB) and interface 23
is saved. Since the metric between 
interfaces 22 and 23, and that between 23 and 22 is assumed to be identical,
the metric between interface 23 and 22 can be omitted in the PCB that is sent to AS 4.
Let interface i be the egress interface the PCB is sent out on. 

In a broader context, this allows us to
include the latency between interfaces i and j if and only if the interface ID
of j is larger than that of i, i.e. id(j)>id(i). 
However, we still need to always include the metric from ingress-
to egress interface regardless of their IDs.

### Clustering

For each metric, interfaces are grouped into clusters, designed to contain interfaces
with roughly similar values of said metric.
We employ a greedy clustering algorithm, which does the following: 

- check for each value in turn if it can be assigned to an already existing cluster
- if yes, add the ID of the associated interface to the cluster
- if not, use this value as the baseline for a new cluster, and add the associated
  ID to this new cluster

The details depend on the metric in question.

## Latency Information

Latency Information refers to the total propagation delay on an end to end
path, comprised of intra- and inter-AS delays and measured on the scale of
milliseconds.
Use cases of such information include:

- Allows to augment path selection policy in order to obtain low latency paths

### Conceptual Implementation Latency

The latency information will be comprised of four main parts:

- The inter-AS latency of the child link between the egress interface and
  the ingress interface of the AS the PCB will be propagated to
- The intra-AS latency between the ingress and egress interface of the AS in the
  absence of shortcut/peering paths
- A variable number of child latency clusters
- A variable number of peering latency clusters

In general, a latency cluster serves to pool all interfaces which have the same
propagation delay (within a 1 ms range) between them and the egress interface (i.e.
the interface the PCB will be sent out on). A peering cluster gathers all peering
interfaces, whereas a child cluster gathers all interfaces attached to a child link.
The difference between peering and child latency clusters is that in peering
latency clusters, the latency of the inter-AS link attached to the interface is also
included in the cluster for every such peering interface. In child clusters
this information is omitted.
A cluster will
include all interfaces with intra-AS delay values in the interval
(baseline, baseline+1(.
Each peering latency cluster is itself comprised of 3 types of elements:

- The intra-AS propagation delay for every interface in the cluster, in ms (1
  value per cluster)
- The interface ID for every interface in the cluster (1 value per interface)
- The inter-AS propagation delay for the connections attached to these
  interfaces, in ms (1 value per interface)

Child latency clusters look almost exactly the same, with the one difference
being that the inter-AS propagation delays are omitted:

- The intra-AS propagation delay for every interface in the cluster, in ms (1
  value per cluster)
- The interface ID for every interface in the cluster (1 value per interface)

In core segments, both child- and peering latency clusters are omitted.

### Concrete Format Latency

The format for latency information, specified in terms of its capnp encoding, looks like this:

````CAPNP
struct LatencyInfo {
  latencyNonpeeringClusters @0 :List(LnpCluster);
  latencyPeeringClusters @1 :List(LpCluster);
  egressLatency @2 :UInt16;
  intooutLatency @3 :UInt16;

  struct LnpCluster {
     clusterDelay @0 :UInt16;
     interfaces @1 :List(UInt16);
  }

  struct LpCluster {
     clusterDelay @0 :UInt16;
     latencyInterfacePairs @1 :List(Lppair);

     struct LpPair {
        interface @0 :UInt16;
        interDelay @1 :UInt16;
     }
  }
}
````

## Maximum Bandwidth

Maximum Bandwidth Information consists of 2 parts, Inter- and Intra-AS:

- Inter-AS Maximum Bandwidth Information describes the maximum bandwidth
  available on the inter-AS connections between each AS.
- Intra-AS Maximum Bandwidth Information describes the smallest maximum
  bandwidth available on any link that lies on the intra-AS routing path,
  i.e. the path from an interface to the egress interface.
  
Bandwidth is measured at the granularity of Kb/s.
Use cases of such information include:

- Allows to augment path selection policy, such that unsuitable paths can be
  excluded a priori
- Avoid connections that are prone to congestion due to a low-bandwidth
  bottleneck somewhere

### Conceptual Implementation Maximum Bandwidth

The maximum bandwidth information will be comprised of 3 main parts:

- A variable number of maximum bandwidth clusters
- The bandwidth of the egress connection
- The intra-AS maximum bandwidth between the ingress and egress interface
  of the AS in the absence of shortcut/peering paths

A maximum bandwidth cluster serves to pool all interfaces which have the
same total maximum bandwidth. For peering interfaces, the total maximum bandwidth
is calculated as the minimum between the intra-AS bandwidth and the bandwidth of
the inter-AS peering link.
A cluster will include all interfaces with values in the
interval (baseline-5, baseline+5(. 
Each cluster is itself formed of 2 types of elements:

- The maximum bandwidth for all interfaces in the cluster (1 value per
  cluster)
- The interface IDs of all the interfaces in the cluster (1 value per interface)

In core segments, the bandwidth clusters are omitted.

### Concrete Format Maximum Bandwidth

The format for maximum bandwidth information, specified in terms of its capnp
encoding, looks like this:

````CAPNP
struct Bandwidthinfo {
  bandwidthClusters @0 :List(BwCluster);
  egressBW @1 :UInt32;
  inToOutBW @2 :UInt32;

  struct BwCluster {
     clusterBW @0 :UInt32;
     interfaces @1 :List(UInt16);
  }
}
````

## Geographic Information

Geographic Information is the full set of GPS coordinates identifying the
location of every SCION border router deployed by an AS, as well as a real
life address associated with the location of each such SCION border router.
Use cases of such information include:

- Can be used to augment path selection policies in order to ensure paths do not
  leave a particular area, or alternatively ascertain that they never cross
  territory that is considered "undesirable" by the user
- Can be used to provide users with information about the location of the entity
  they are communicating with (i.e. the endpoint on the other side of the path)
- Informing network admins about router locations

### Conceptual Implementation Geographic Information

The geographic information will be comprised of 1 main part:

- A variable number of location clusters

A location cluster serves to pool all interfaces which are located in the same
geographic location (i.e. same address). Each location cluster is itself formed
of 2 main types of elements:

- The location of the cluster, consisting of a pair of GPS coordinates
  describing latitude and longitude, as well as a civic address, in the format
  specified in RFC 4776 (found
  <a href = "https://tools.ietf.org/html/rfc4776#section-3.3"> here </a>)
  (1 value in total)
- The interface ID for every interface in the cluster (1 value per interface)

It is possible to use only the latititude and longitude pair, or the civic
address by simply omitting one of the two.


### Concrete Format Geographic Information

The format for geographic information looks like this:

````CAPNP
struct GeoInfo {
  geoClusters @0 :List(GeoCluster);

  struct GeoCluster {
     location @0 :ClusterLocation;
     interfaces @1 :List(UInt16);

     struct ClusterLocation {
        latitude @0 :Float32;
        longitude @1 :Float32;
        civilAddress @2 :Data;
     }
  }
}
````

It should be noted that civil addresses (`civilAddress`) can be of variable length,
but are allowed to occupy a maximum of 500 bytes. Anything beyond that will
be discarded.

## Link Type

### Definition Link Type

Link Type information gives a broad classification of the different protocols
being used on the links between two entities.
For now it distinguishes three different types of links:

- Links that go over the open internet
- Direct links
- Multihop links

Use cases of such information include:

- Mitigating security concerns
- Allowing users to select paths that e.g. avoid the open internet

### Conceptual Implementation Link Type

The Link type will be comprised of 2 parts:

- The link type for the inter-AS link attached to the egress interface
- The inter-AS link type of all links attached to peering interfaces

The latter is omitted in core segments.

### Concrete Format Link Type

The format for the link type looks like this:

````CAPNP
struct LinktypeInfo {
  peeringLinks @0 :List(PeeringPair);
  egressLinktype @1 :Linktype;

  enum Linktype{
     direct @0;
     multiHop @1;
     openNet @2;
  }

  struct PeeringPair {
     interface @0 :UInt16;
     peeringInterLinktype @1 :Linktype;
  }
}
````

## Number of Internal Hops

The Number of Internal Hops describes how many hops are on the Intra-AS path.
Use cases of such information include:

- Can be used to exclude undesireable paths from the selection
- Obtain a selection of efficient, low latency paths (especially when combined
  with Latency Information)

### Conceptual Implementation Number of Internal Hops

The number of internal hops will be comprised of 2 main parts:

- The number of internal hops between the ingress and egress interface of the
  AS in the absence of shortcut/peering paths
- A variable number of hoplength clusters

A hoplength cluster serves to pool all interfaces which have the same number of
internal hops on the intra-AS path between them and the egress interface. Each
hoplength cluster is itself formed of 2 main elements:

- The number of internal hops for all interfaces in the cluster (1 value per
  cluster)
- The interface ID for every interface in the cluster (1 value per interface)

### Concrete Format Number of Internal Hops

The format for the number of internal hops looks like this:

````CAPNP
struct InternalHopsInfo {
  hopClusters @0 :List(HopCluster);
  inToOutHops @1 :UInt8;

  struct HopCluster {
     clusterHops @0 :UInt8;
     interfaces @1 :List(UInt16);
  }
}
````

## Note

A Note is simply a bit of plaintext.
Use cases of such information include:

- Tool for network engineers to communicate interesting/important information to
  their peers as well as users

### Conceptual Implementation Note

The Note subtype is comprised of 1 single element:

- A string

### Concrete Format Note

The format for the note can be seen below in the full extension format.

The length `note` is variable, but capped at 2000 bytes. 

## Concrete Format Extension

The full wire format of the extension simply combines the capnp structs for each individual
property described above:

````CAPNP
struct StaticInfo {
   latencyInfo @0 :LatencyInfo;
   geoInfo @1 :GeoInfo;
   linktypeInfo @2 :LinktypeInfo;
   bandwidthInfo @3 :BandwidthInfo;
   internalHopsInfo @4 :InternalHopsInfo;
   note @5 :Text;
}
````

## Config File Format

In order for the extension to work, a config file needs to be provided to a
specific location [tbd]. The config file comes in the form of a JSON file
and needs to have the format shown below.
The interfaces are divided into two categories, the first being nonpeering
interfaces, and the second being peering interfaces.
Regardless of category, for every interface `i` the same values can be provided
as listed below:

Name             | Type  | Description |
-----------------|-------|-------------|
`ID`         |Integer|Interface ID of the interface described by the data that follows|
`Intra` (`Latency`)   |List of Integers|Intra-AS latency from interface `i` to every other interface in the AS, including itself (this entry should normally be set to 0)|
`Inter` (`Latency`)   |Integer|Inter-AS latency from interface `i` to AS on the other end of the link|
`Latitude`             |Decimal value|Longitude gps coordinates of interface `i`|
`Longitude`             |Decimal value|Latitude gps coordinate of interface `i`|
`CivAddr`        |String|Civic address of interface `i`|
`Inter` (`Linktype`)      |Integer  |Possible values of an entry : `multihop`, `direct`, `opennet`, where `direct` means direct link, `multihop` means multihop link, `opennet` means link that uses the open internet. Describes link type between interface `i` and the AS at the other end of the link|
`Intra` (`Bandwidth`)        |Integer|Intra-AS bandwidth from interface `i` to every other interface in the AS, including itself (this entry should normally be set to 0)|
`Inter` (`Bandwidth`)        |Integer|Inter-AS bandwidth from interface i to the AS at the other end of the link|
`Note`   |String |Note |
`Intra` (`Hops`)           |Integer|Number of internal hops from interface `i` to every other interface in the AS, including itself (this entry should normally be set to 0)|

Below is a simple example of how such a config file could look like (actual
values are abitrary, "asdf" is used as a placeholder for longer strings)
for an AS with three interfaces with IDs 1, 2, 3 and 5:

````JSON
{
  "Latency": {
    "1":{
      "Inter": 30,
      "Intra": {
        "1": 0,
        "2": 10,
        "3": 20,
        "5": 30
      }
    },
    "2":{
      "Inter": 40,
      "Intra": {
        "1": 50,
        "2": 0,
        "3": 60,
        "5": 70
      }
    },
    "3":{
      "Inter": 80,
      "Intra": {
        "1": 90,
        "2": 100,
        "3": 0,
        "5": 110
      }
    },
    "5":{
      "Inter": 120,
      "Intra": {
        "1": 130,
        "2": 140,
        "3": 150,
        "5": 0
      }
    }
  },
  "Bandwidth": {
    "1":{
      "Inter": 400000000,
      "Intra": {
        "1": 0,
        "2": 100000000,
        "3": 200000000,
        "5": 300000000
      }
    },
    "2":{
      "Inter": 4000000000,
      "Intra": {
        "1": 5044444,
        "2": 0,
        "3": 6555555550,
        "5": 75555550
      }
    },
    "3":{
      "Inter": 80,
      "Intra": {
        "1": 9333330,
        "2": 10444440,
        "3": 0,
        "5": 133333310
      }
    },
    "5":{
      "Inter": 120,
      "Intra": {
        "1": 1333330,
        "2": 155555540,
        "3": 15666660,
        "5": 0
      }
    }
  },
  "Linktype": {
    "1":{
      "Inter": "direct"
    },
    "2":{
      "Inter": "opennet"
    },
    "3":{
      "Inter": "direct"
    },
    "5":{
      "Inter": "direct"
    }
  },
  "Geo": {
    "1":{
      "Latitude": 47.2,
      "Longitude": 62.2,
      "CivAddr": "geo1"
    },
    "2":{
      "Latitude": 79.2,
      "Longitude": 45.2,
      "CivAddr": "geo2"
    },
    "3":{
      "Latitude": 47.22,
      "Longitude": 42.23,
      "CivAddr": "geo3"
    },
    "5":{
      "Latitude": 48.2,
      "Longitude": 46.2,
      "CivAddr": "geo5"
    }
  },
  "Hops": {
    "1":{
      "Intra": {
        "1": 0,
        "2": 2,
        "3": 3,
        "5": 0
      }
    },
    "2":{
      "Intra": {
        "1": 2,
        "2": 2,
        "3": 3,
        "5": 0
      }
    },
    "3":{
      "Intra": {
        "1": 4,
        "2": 6,
        "3": 3,
        "5": 3
      }
    },
    "5":{
      "Intra": {
        "1": 2,
        "2": 3,
        "3": 4,
        "5": 0
      }
    }
  },
  "Note": "asdf"
}
````

## Command Line Interface

In order to make use of the information this extension provides, we will provide a command line interface (CLI) to extract data from the extension. This CLI will be implemented as an extension of the current showpaths tool.
To display information about the static properties, showpaths can be called with the flag `-staticinfo` and the following values will be displayed:

Name               | Description |
-------------------|-------------|
EndToEndLatency | Minimal end to end propagation delay along the entire path|
Geo | Geographical location in terms of GPS coordinates of each AS on the path (achieved by displaying the geographical locations of all interfaces of the AS)|
MaxBW | Bottleneck maximum bandwidth along the entire path|
InternalHops | The number of internal hops along the entire path|
Linktypes| The link type of each inter-AS connection along the entire path| 
Notes | The notes for each AS on the path|



