# Path Policy Language Design

The path policy language will be used by the path server, SCIOND and the beacon server for different
but overlapping purposes.

## Interface Predicate (IFP)

An interface predicate is of the form **ISD-AS#IF**, whereas _0_ can be used as a wildcard for
**ISD**, **AS** and **IF** indepedently. If the **AS** identifier is set to _0_, the **IF**
identifier must also be set to _0_.

Examples:

-   Match interface _2_ of AS _1-ff00:0:133_: `1-ff00:0:133#2`
-   Match any interface of AS _1-ff00:0:133_: `1-ff00:0:133#0` or `1-ff00:0:133`
-   Match any interface in ISD _1_: `1-0#0`, `1-0` or `1`

## Operators

The path policy language has the following operators:

ACL:

-   `+` (allow predicate)
-   `-` (deny predicate)

Sequence:

-   `?` (the preceding IFP may appear at most once)
-   `+` (the preceding IFP must appear at least once)
-   `!` (logical NOT)
-   `|` (logical OR)
-   `&` (logical AND)

## Policy

A policy is defined by a policy object. It can have the following attributes:

-   [`sequence`](#Sequence) (space separated list of IFPs, may contain operators)
-   [`acl`](#ACL) (list of IFPs, preceded by `+` or `-`)

Planned:

-   `bw` (bandwidth)
-   `lat` (latency)
-   `cost`
-   `mtu`
-   `exp` (expiration time)
-   `frh` (freshness)
-   `hops` (number of hops)
-   `type` (defines where the policy should apply)
-   `peer` (peer segments)
-   `shct` (shortcut segments)

Policies can be composed in two ways. The first option is to extend an existing policy:

-   [`extends`](#Extends) (list of policy names)

The extending policy gets the attributes of the extended policy and overwrites duplicate attributes.

The second option is to specify a list of _option_ policies from which the highest weighted policy
that fulfills the condition is used. If policies have the same weight, their combined results are
returned.

-   [`options`](#Options) (list of policy names)
-   `weight` (weight number)

## Format

The policy language can be in different formats, currently we want to add support for `YAML`, `JSON`
and `TOML`.

## Specification

### ACL

The ACL can be used to white- and blacklist ISDs, ASes and IFs. The first match wins and an explicit
default action needs to be supplied. If the `acl` attribute is not used as part of a policy, by
default everything is whitelisted.

The following is an example for allowing all interfaces in ASes _1-ff00:0:133_ and _1-ff00:0:120_,
but denying all other ASes in ISD _1_. The last entry makes sure that any other ISD is allowed.

```
- acl_policy_example:
  acl:
  - '+ 1-ff00:0:133'
  - '+ 1-ff00:0:120'
  - '- 1'
  - '+'
```

### Sequence

The sequence is a string of space separated IFPs. The [operators](#Operators) can be used for
advanced interface sequences.

The following example specifies a path from any interface in AS _1-ff00:0:133_ to two subsequent
interfaces in AS _1-ff00:0:120_ (entering on interface _2_ and exiting on interface _1_), then there
are two wildcards that each match any AS. The path must end with any interface in AS _1-ff00:0:110_.

```
- sequence_example_1:
  sequence: "1-ff00:0:133#0 1-ff00:0:120#2 1-ff00:0:120#1 0 0 1-ff00:0:110#0"
```

Another possible way of expressing the same behaviour:

```
- sequence_example_2:
  sequence: "1-ff00:0:133#0 1-ff00:0:120#2,1 0 0 1-ff00:0:110#0"
```

Any path that is matched by the above policy must traverse three transit ASes. In many cases the
number of ASes or hops is not know. With the regex-style it is possible to express such sequences.

The following example specifies a path from interface _1-ff00:0:133#1_ through multiple ASes in ISD
_1_, that may (but does not need to) traverse AS _2-ff00:0:1_ and then reaches its destination on
_2-ff00:0:233#1_.

```
- sequence_more_complex:
  sequence: "1-ff00:0:133#1 1+ 2-ff00:0:1? 2-ff00:0:233#1"
```

### Extends

Path policies can be composed by extending other policies. The `extends` attribute requires a list
of named policies. If an attribute exists in multiple policies in that list, the last occurence has
precedence. Also, an attribute specified at top level (the policy that has the `extends` attribute)
always has precedence over attributes of an extended policy.

The following example uses two sub-policies to create the top-level policy.

```
- extends_example:
  extends:
  - sub_pol_1
  - sub_pol_2

- sub_pol_1:
  acl:
  - "- 1-ff00:0:133#0"
  - "+"

- sub_pol_2:
  sequence: "0+ 1-ff00:0:110#0 1-ff00:0:110#0 0+"
```

### Options

The `options` attribute requires a list of anonymous policies. Each policy may have `weight` as an
attribute to specify its importance and may have all other attributes of a policy. Options are
evaluated in the order of their weight. The paths of the policy with the highest weight are used, if
the heighest-weight policy does not match any paths, the next policy is evaluated. When multiple
policies have the same weight, all of their paths are returned. The default for a weight (when it is
omitted) is 0.

The following example has three options, the first denies ISD 1. If that doesn't match any paths,
the second option which denies hops in multiple ASes is used. If that again does not match, the
third option which denies only hops in AS _1-ff00:0:133_, is used.

```
- policy_with_options:
  options:
    - weight: 3
      extends: option_3
    - weight: 2
      acl:
      - "- 1-ff00:0:130#0"
      - "- 1-ff00:0:131#0"
      - "- 1-ff00:0:132#0"
      - "+"
    - extends: option_1

- option_3:
  acl:
  - "- 1-0#0"
  - "+"
- option_1:
  acl:
  - "- 1-ff00:0:133#0"
  - "+"
```
