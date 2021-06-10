SessionPolicy
-------------
A Session Policy describes the traffic configuration to a remote AS. It contains

- a Policy ID uniquely identifying the Session Policy
- a Traffic Class defining the set of IP packets that are forwarded in this Session
- a Path Class defining the set of paths that can be used to forward the IP packets
- a Performance Policy defining an ordering on the set of allowed paths with respect to a certain optimization goal
- a Path Count defining the number of paths used simultaneously to load balance different flows in the Session

Traffic Class
-------------

A Traffic Class defines a classification of IP packets. All IP packets that
match the matching criteria of the Traffic Class belong to that class. A Traffic
Class has a Name and a Traffic Matcher

Traffic Matcher
---------------

A Traffic Matcher defines the matching criteria for a Traffic Class. The
matching criteria is defined using the traffic classification language, e.g., ::

  # match all packets with a dest IP in this prefix
  dst=192.168.1.0/24
  # match all packets with a given dest IP or given DSCP bits
  any(dst=192.168.1.0/24, dscp=0xb2)

Path Class
----------

A Path Class defines a classification of paths. All paths that match the
matching criteria of the Path Class belong to that class. A Path Class has a
Name and a Path Matcher.

Path Matcher
------------

A Path Matcher defines the matching criteria for a Path Class. The matching
criteria is defined using the path policy language, e.g., ::

  # blacklist paths containing AS 111 (in any ISD). Allow everything else.
  acl:
    - 0-111#0
    + 0
  # Matches all paths that consisting of any number of interfaces,
  # followed by interface 1 in AS 111 followed by at least one other interface.
  sequence: 0* 0-111#1 0+

Performance Policy
------------------

A Performance Policy defines the performance metric that should be optimized
when making a path selection. Possible values can be shortest_path, latency,
jitter, droprate, or mix (take a weighted score across all metrics) (note, not
all of these are currently implemented and are subject to change). A Performance
Policy is used to order the set of paths defined by a Path Class.

Path Count
----------

The Path Count defines the number of paths that can be simultaneously used
within a Session. Default is 1.

How it all fits together
------------------------

A gateway has one or multiple Session Policies per remote AS. The Traffic Class
defines the set of IP packets which are forwarded by the configuration. A Path
Class defines the set of possible paths that can be used by this configuration.
A Performance Policy orders the set of possible paths according to the some
metric. Finally, PathCount defines how many paths are being used simultaneously
within a configuration.
