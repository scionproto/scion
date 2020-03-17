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

## Static Properties

For the purpose of this document, we will adhere to the following definition:
A static property is any quantifiable piece of information describing a
property of a SCION path segment that remains unchanged over the entire
duration of the lifetime of that path segment.

The following assumptions are made:

- The Beacon Service, which is responsible for adding all this metadata, has
  reliable information about the infrastructure (such as the border routers
  and the interfaces attached to them)
- The Beacon Service has access to a blackbox (which could be the AS itself,
  a dedicated SCION service or any other entity), which provides information
  that characterizes the AS topology and the routing processes within the AS
- The AS topology remains stable throughout the lifetime of a path segment

When discussing static properties, we always need to distinguish between
inter-AS and intra-AS elements. Most properties will be comprised of both.
Using the diagram below, the concept of this difference between intra-AS
and inter-AS elements will be illustrated with the example of propagation
delay.

![Inter VS Intra Metrics](fig/inter_vs_intra_metrics.png)

The PCB originates in AS 3, and is then propagated to AS 1, and then to
AS 2. In the AS Entry of AS 1, interface 1 is the ingress and inteface 2
the egress interface. In order to be able to calculate the end-to-end
propagation delay of a path starting in AS 2 and ending in AS 3, we need
both the delay inside each AS (intra-AS), as well as the delay on the
connections between ASes (inter-AS). When measuring intra-AS latency,
the egress interface is the "target" interface, to which the latency is
measured from any other interface (as we will see later, only having the
latency between the ingress and egress interface is not sufficient).
When it comes to inter-AS metrics, we will always extend the PCB only with
the metrics describing the outgoing connection (i.e. the connection that is
used to propagate the PCB to the next AS) in the PCB. Looking at the figure
above, this would mean that AS 1 would extend the PCB with information about the
connection between interface 2 and interface 3 before propagating it to AS 2.
This assures that:

- The PCB always carries information about the entire path
it has traversed so far
- The final AS in the path does not need to make additions/modifications to the
data it receieved through the PCB before being able to use said data

Using this method, we can then calculate the end-to-end delay by simply combining
intra- and inter-AS delays. These concepts appliy similarly to many other
properties. We will now discuss the properties we will embed and the
information that needs to be provided for each of them.

## Latency Information

Latency Information refers to the total propagation delay on an end to end
path, comprised of intra- and inter-AS delays and measured on the scale of
milliseconds.
Use cases of such information include:

- Allows to augment path selection policy in order to obtain low latency paths

### Conceptual Implementation Latency

The latency information will be comprised of four main parts:

- The inter-AS latency between the egress interface and the ingress interface of
  the AS the PCB will be propagated to
- The intra-AS latency between the ingress and egress interface of the AS in the
  absence of shortcut/peering paths
- A variable number of non-peering latency clusters
- A variable number of peering latency clusters


In general, a latency cluster serves to pool all interfaces which have the same
propagation delay (within a 1 ms range) between them and the egress interface (i.e.
the interface the PCB will be sent out on). 
The difference between peering and non-peering latency clusters is that in peering
latency clusters, the latency of the inter-AS link attached to the peering interface is also
included in the cluster for every such peering interface. In non-peering clusters
this information is omitted.
The clustering process is straightforward. When doing clustering, it will simply
pick the first value it comes across that can't be assigned to an already
existing cluster and, if it is not an integer, round it down to the nearest integer.
This value will then serve as the baseline for the newly created cluster, which will
include all interfaces with intra-AS delay values in the interval
(baseline, baseline+1(.
Each peering latency cluster is itself comprised of 3 types of elements:

- The intra-AS propagation delay for every interface in the cluster, in ms (1
  value per cluster)
- The interface ID for every interface in the cluster (1 value per interface)
- The inter-AS propagation delay for the connections attached to these
  interfaces, in ms (1 value per interface)

Non-peering latency clusters look almost exactly the same, with the one difference
being that the inter-AS propagation delays are omitted:

- The intra-AS propagation delay for every interface in the cluster, in ms (1
  value per cluster)
- The interface ID for every interface in the cluster (1 value per interface)

Information about the inter-AS latency, as well as the intra-AS latency from
every interface to the egress interface is required to deal with peering
paths (see diagram).

![Normal Path](fig/normal_paths_with_labels.png)

In the case of a "normal", the interfaces where traffic enters
and leaves correspond to the ingress and egress interfaces respectively, that are
saved in the AS Entry of the PCB. The terms ingress and egress interfaces refer to
the way these interfaces would be encoded in the PCB during the beaconing process,
therefore the lower interface is always labelled as the egress interface, even when it is in
the up segment and would thus technically be the interface on which traffic enters the AS.
Calculating end-to-end latencies can therefore be done by simply adding up the intra-AS
latency (from ingress to egress interface) as well as the inter-AS latency (from egress
interface to the next AS on the path) for every AS on the end to end path.

Knowing merely the inter-AS latency for the egress interface is also sufficient
in the case of shortcut paths. Traffic will enter AS 2 via interface 22, which
is the egress interface saved in the AS Entry for AS 2 in the PCB which was directly
received by AS 3. Traffic will leave AS 2 via interface 21, which is the interface that
was saved in AS Entry of the PCB that was sent to AS 4 and was fetched by AS 3 in
the form of a path segment during the path lookup process. Thus AS 3 now has information
about both the inter-AS connection between AS 3 and AS 2, and the inter-AS connection
between AS 2 and AS 4. In the presence of information about intra-AS latencies, 
this information is sufficient to calculate the end-to-end latency betwen AS 3 and AS 4
(see figure below). Thus, for non-peering interfaces, we will only encode the inter-AS
latency for the egress interface in the latency information.

Peering connections need to be dealt with separately. A peering link may differ
from the egress interface encoded in any of the AS Entries of any of the path segments that
were received or fetched by AS 3. Therefore we need to make sure that the inter-AS latency
for every connection attached to a peering interface of the AS is also stored in the PCB
(this is done in the peering latency clusters) (see figure below).

Intra-AS delays present a problem in the presence of both shortcut-, or peering
paths. In those situations, merely 
storing the latency from the ingress to the egress interface will be insufficient.
This is because the interface on which traffic will leave the AS as it travels
along the path will no longer be the ingress interface encoded in the PCB that
was used to construct the up segment, but rather either the egress interface
stored in a different PCB (in the case of a shortcut connection) or a peering
interface (in the case of a peering conncetion). Therefore, it is necessary
that latencies (or other metrics when looking at a different property) be known
for the paths from the egress interface to such a non-ingress interface also
(see figure below).

![Shortcut Path](fig/shortcut_paths_with_labels.png)
![Peering Path](fig/peering_paths_with_labels.png)

In the case of non-peering connections, we will also make an additional assumption
in order to reduce the amount of data we need to include in the PCBs in total. That
assumption being that intra-AS latencies are symmetric. We can illustrate the use of
this assumption using the drawing of a shortcut path above. In the PCB sent to AS 3,
the latency between interface 22 (the egress interface for this PCB) and interface 23
is saved. Now is when the assumption comes into play. Since the latency between 
interfaces 22 and 23, and that between 23 and 22 is identical, we can omit the latency
between interface 23 and 22 in the PCB that is sent to AS 4. Let interface i be the
egress interface the PCB is sent out on. The this approach ultimately allows us to
always omit the latency between interfaces i and j, in the case that the interface ID
of j is smaller than that of i, or expressed as a formula, id(j)<id(i). This also
means that when it comes to non-peering interfaces, we need only include those with
an ID bigger than the ID of the egress interface in the latency clusters. If this means
a cluster would contain no interface IDs anymore, we simply omit it as a whole.
However, in order to still be able to obtain the intra AS latency in the case where
the ID of the ingress interface is smaller than that of the egress interface and the
AS does not serve as a shortcut AS, we will always include the latency from ingress-
to egress interface.

All these considerations also apply to other properties, such as maximum bandwidth
(see below).

### Concrete Format Latency

The format for latency information, specified in terms of its capnp encoding, looks like this:

````CAPNP
struct Latencyinfo {
  latencynonpeeringclusters @0 :List(Lnpcluster);
  latencypeeringclusters @1 :List(Lpcluster);
  egresslatency @2 :UInt16;
  intooutlatency @3 :UInt16;

  struct Lnpcluster {
     clusterdelay @0 :UInt16;
     interfaces @1 :List(UInt16);
  }

  struct Lpcluster {
     clusterdelay @0 :UInt16;
     latencyinterfacepairs @1 :List(Lppair);

     struct Lppair {
        interface @0 :UInt16;
        interdelay @1 :UInt16;
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
When doing clustering, the system will simply pick the first value it comes across
that can't be assigned to an already existing cluster and, if it is not an integer,
round it down to the nearest integer. This value will then serve as the
baseline for the newly created cluster, which will include all interfaces with
delay values in the interval (baseline, baseline+10(.
Each cluster is itself formed of 2 types of elements:

- The maximum bandwidth for all interfaces in the cluster (1 value per
  cluster)
- The interface IDs of all the interfaces in the cluster (1 value per interface)

Be reminded that only the interfaces with
IDs bigger than the ID of the egress interface are included, and if this would mean a
cluster is devoid of interface IDs, the cluster is simply removed as a whole.

### Concrete Format Maximum Bandwidth

The format for maximum bandwidth information, specified in terms of its capnp
encoding, looks like this:

````CAPNP
struct Bandwidthinfo {
  bandwidthclusters @0 :List(Bwcluster);
  egressBW @1 :UInt32;
  intooutBW @2 :UInt32;

  struct Bwcluster {
     clusterbw @0 :UInt32;
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
struct Geoinfo {
  geoclusters @0 :List(Geocluster);

  struct Geocluster {
     location @0 :Clusterlocation;
     interfaces @1 :List(UInt16);

     struct Clusterlocation {
        latitude @0 :Float32;
        longitude @1 :Float32;
        civiladdress @2 :Data;
     }
  }
}
````

It should be noted that civil addresses (`civiladdress`) can be of variable length,
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

### Concrete Format Link Type

The format for the link type looks like this:

````CAPNP
struct Linktypeinfo {
  peeringlinks @0 :List(Peeringpair);
  egresslinktype @1 :Linktype;

  enum Linktype{
     direct @0;
     multihop @1;
     opennet @2;
  }

  struct Peeringpair {
     interface @0 :UInt16;
     peeringinterlinktype @1 :Linktype;
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
struct Internalhopsinfo {
  hopclusters @0 :List(Hopcluster);
  intouthops @1 :UInt8;

  struct Hopcluster {
     clusterhops @0 :UInt8;
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

The Note subtype is comprised of 2 elements:

- The "default" field, which contains a default note, which is always included for
  every PCB that is propagated by this AS.
- The "specific" field, which contains the contents of a note that is meant to only
  be attached when sending out a PCB over the particular interface mentioned in the
  egress interface field of the AS Entry that we are extending.
  
When constructing the extension from the config file (see below) the BS will check
the egress interface field in the AS Entry and attach the "specific" note accordingly.
If no such note is specified in the config file, then the contents of the "specific"
field will be set to null (it is also possible to do this for the "default" note as
well).

### Concrete Format Note

The format for the note looks like this:

````CAPNP
struct Note {
  defaultnote @0 :Data;
  specificnote @1 :Data;
}
````

The lengths of both `defaultnote` and `specificnote` are variable, but capped at 2000 bytes. 

## Concrete Format Extension

The full wire format of the extension simply combines the capnp structs for each individual
property described above:

````CAPNP
struct Staticinfo {
   ei @0 :Latencyinfo;
   gi @1 :Geoinfo;
   lt @2 :Linktypeinfo;
   bw @3 :Bandwidthinfo;
   ih @4 :Internalhopsinfo;
   ni @5 :Note;
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
`Peer`      |Boolean|Indicates whether an interface is a peering interface|
`Delay`   |List of Integers|Intra-AS latency from interface `i` to every other interface in the AS, including itself (this entry should normally be set to 0)|
`Inter` (`Latency`)   |Integer|Inter-AS latency from interface `i` to AS on the other end of the link|
`C1`             |Decimal value|Longitude gps coordinates of interface `i`|
`C2`             |Decimal value|Latitude gps coordinate of interface `i`|
`CivAddr`        |String|Civic address of interface `i`|
`Inter` (`Linktype`)      |Integer  |Possible values of an entry : `multihop`, `direct`, `opennet`, where `direct` means direct link, `multihop` means multihop link, `opennet` means link that uses the open internet. Describes link type between interface `i` and the AS at the other end of the link|
`BW`        |Integer|Intra-AS bandwidth from interface `i` to every other interface in the AS, including itself (this entry should normally be set to 0)|
`Inter` (`Bandwidth`)        |Integer|Inter-AS bandwidth from interface i to the AS at the other end of the link|
`Note`   |String |Note |
`HN`           |Integer|Number of internal hops from interface `i` to every other interface in the AS, including itself (this entry should normally be set to 0)|

Below is a simple example of how such a config file could look like (actual
values are abitrary, "asdf" is used as a placeholder for longer strings)
for an AS with three interfaces with IDs 1, 2, 3 and 5:

````JSON
{
  "Latency": [
    {
      "ID": 1,
      "Peer": false,
      "Inter": 30,
      "Intra": [
        {
          "ID": 1,
          "Delay": 0
        },
        {
          "ID": 2,
          "Delay": 10
        },
        {
          "ID": 3,
          "Delay": 20
        },
        {
          "ID": 5,
          "Delay": 30
        }
      ]
    },
    {
      "ID": 2,
      "Peer": false,
      "Inter": 20,
      "Intra": [
        {
          "ID": 1,
          "Delay": 10
        },
        {
          "ID": 2,
          "Delay": 0
        },
        {
          "ID": 3,
          "Delay": 30
        },
        {
          "ID": 5,
          "Delay": 40
        }
      ]
    },
    {
      "ID": 3,
      "Peer": false,
      "Inter": 15,
      "Intra": [
        {
          "ID": 1,
          "Delay": 20
        },
        {
          "ID": 2,
          "Delay": 30
        },
        {
          "ID": 3,
          "Delay": 0
        },
        {
          "ID": 5,
          "Delay": 60
        }
      ]
    },
    {
      "ID": 5,
      "Peer": true,
      "Inter": 24,
      "Intra": [
        {
          "ID": 1,
          "Delay": 10
        },
        {
          "ID": 2,
          "Delay": 30
        },
        {
          "ID": 3,
          "Delay": 20
        },
        {
          "ID": 5,
          "Delay": 40
        }
      ]
    }
  ],
  "Bandwidth": [
    {
      "ID": 1,
      "Peer": false,
      "Inter": 1000000,
      "Intra": [
        {
          "ID": 1,
          "BW": 0
        },
        {
          "ID": 2,
          "BW": 1500000
        },
        {
          "ID": 3,
          "BW": 2000000
        },
        {
          "ID": 5,
          "BW": 3000000
        }
      ]
    },
    {
      "ID": 2,
      "Peer": false,
      "Inter": 2200000,
      "Intra": [
        {
          "ID": 1,
          "BW": 1000098
        },
        {
          "ID": 2,
          "BW": 0
        },
        {
          "ID": 3,
          "BW": 38778770
        },
        {
          "ID": 5,
          "BW": 4879770
        }
      ]
    },
    {
      "ID": 3,
      "Peer": false,
      "Inter": 15789789,
      "Intra": [
        {
          "ID": 1,
          "BW": 20789789
        },
        {
          "ID": 2,
          "BW": 30789879
        },
        {
          "ID": 3,
          "BW": 78978978
        },
        {
          "ID": 5,
          "BW": 60456456
        }
      ]
    },
    {
      "ID": 5,
      "Peer": true,
      "Inter": 2467867,
      "Intra": [
        {
          "ID": 1,
          "BW": 10435663446
        },
        {
          "ID": 2,
          "BW": 303333333
        },
        {
          "ID": 3,
          "BW": 203333333
        },
        {
          "ID": 5,
          "BW": 40444444
        }
      ]
    }
  ],
  "Linktype": [
    {
      "ID": 1,
      "Peer": false,
      "Inter": "direct"
    },
    {
      "ID": 2,
      "Peer": false,
      "Inter": "opennet"
    },
    {
      "ID": 3,
      "Peer": false,
      "Inter": "direct"
    },
    {
      "ID": 5,
      "Peer": true,
      "Inter": "direct"
    }
  ],
  "Geo": [
    {
      "ID": 1,
      "Peer": false,
      "C1": 47.2,
      "C2": 62.2,
      "CivAddr": "geo1"
    },
    {
      "ID": 2,
      "Peer": false,
      "C1": 79.2,
      "C2": 45.2,
      "CivAddr": "geo2"
    },
    {
      "ID": 3,
      "Peer": false,
      "C1": 47.22,
      "C2": 42.23,
      "CivAddr": "geo3"
    },
    {
      "ID": 5,
      "Peer": true,
      "C1": 48.2,
      "C2": 46.2,
      "CivAddr": "geo5"
    }
  ],
  "Hops": [
    {
      "ID": 1,
      "Peer": false,
      "Intra": [
        {
          "ID": 1,
          "HN": 0
        },
        {
          "ID": 2,
          "HN": 2
        },
        {
          "ID": 3,
          "HN": 3
        },
        {
          "ID": 5,
          "HN": 0
        }
      ]
    },
    {
      "ID": 2,
      "Peer": false,
      "Intra": [
        {
          "ID": 1,
          "HN": 2
        },
        {
          "ID": 2,
          "HN": 2
        },
        {
          "ID": 3,
          "HN": 1
        },
        {
          "ID": 5,
          "HN": 1
        }
      ]
    },
    {
      "ID": 3,
      "Peer": false,
      "Intra": [
        {
          "ID": 1,
          "HN": 1
        },
        {
          "ID": 2,
          "HN": 2
        },
        {
          "ID": 3,
          "HN": 0
        },
        {
          "ID": 5,
          "HN": 4
        }
      ]
    },
    {
      "ID": 5,
      "Peer": true,
      "Intra": [
        {
          "ID": 1,
          "HN": 2
        },
        {
          "ID": 2,
          "HN": 1
        },
        {
          "ID": 3,
          "HN": 6
        },
        {
          "ID": 5,
          "HN": 0
        }
      ]
    }
  ],
  "Note": "asdf"
}
````






