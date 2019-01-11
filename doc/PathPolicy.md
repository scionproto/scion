# Path Policy Language Design

The path policy language will be used by the path server, SCIOND and the beacon server for different
but overlapping purposes.

## Hop Predicate (HP)

A hop predicate is of the form **ISD-AS#IF**, where _0_ can be used as a wildcard for **ISD**,
**AS** and **IF** indepedently. If the **AS** identifier is set to _0_, the **IF** identifier must
also be set to _0_. To specify both interfaces of an AS, one must separate them by `,` ie.
**ISD-AS#IF1,IF2**.

If the tail elements in a HP are 0, they can be omitted. See the following examples for details.

Examples:

-   Match interface _2_ and _3_ of AS _1-ff00:0:133_: `1-ff00:0:133#2,3`"
-   Match interface _2_ of AS _1-ff00:0:133_: `1-ff00:0:133#2`
-   Match any interface of AS _1-ff00:0:133_: `1-ff00:0:133#0` or `1-ff00:0:133`
-   Match any interface in ISD _1_: `1-0#0`, `1-0` or `1`

## Operators

The path policy language has the following operators:

ACL:

-   `+` (allow predicate)
-   `-` (deny predicate)

Sequence:

-   `?` (the preceding HP may appear at most once)
-   `+` (the preceding **ISD-level** HP must appear at least once)
-   `*` (the preceding **ISD-level** HP may appear zero or more times)
-   `!` (logical NOT)
-   `|` (logical OR)
-   `&` (logical AND)

## Policy

A policy is defined by a policy object. It can have the following attributes:

-   [`extends`](#Extends) (list of extended policies)
-   [`acl`](#ACL) (list of HPs, preceded by `+` or `-`)
-   [`sequence`](#Sequence) (space separated list of HPs, may contain operators)
-   [`options`](#Options) (list of option policies)
    -   `weight` (importance level, only valid under `options`)

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

## Specification

### ACL

The ACL can be used to deny (blacklist) or allow (whitelist) ISDs, ASes and IFs. A deny entry is of
the following form `- ISD-AS#IF`, where the second part is a [HP](#HP). If a deny entry matches any
hop on a path, the path is not allowed.

An allow entry uses `+` with a HP, ie. `+ ISD-AS#IF`. For a path to be allowed, every hop of the
path must be allowed by the ACL. When using allow and deny entries in the same ACL, the first
matched entry wins. Thus, if an interface is denied by the first entry but allowed by the second
entry it is still denied.

Every ACL must end with a blanket accept or deny (i.e. `+` or `-`, or equivalent such as `+ 0-0#0`).
If a policy has no acl attribute (and doesn't inherit one from any policy it extends), then by
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

The sequence is a string of space separated HPs. The [operators](#Operators) can be used for
advanced interface sequences.

The following example specifies a path from any interface in AS _1-ff00:0:133_ to two subsequent
interfaces in AS _1-ff00:0:120_ (entering on interface _2_ and exiting on interface _1_), then there
are two wildcards that each match any AS. The path must end with any interface in AS _1-ff00:0:110_.

```
- sequence_example_2:
    sequence: "1-ff00:0:133#0 1-ff00:0:120#2,1 0 0 1-ff00:0:110#0"
```

Any path that is matched by the above policy must traverse three transit ASes. In many cases the
number of ASes or hops is not known. With the regex-style it is possible to express such sequences.

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

The following example uses three sub-policies to create the top-level policy. As `sub_pol_1` and
`sub_pol_3` both define an ACL but `sub_pol_3` has precedence, the ACL of `sub_pol_1` is discarded.

```
- extends_example:
    extends:
    - sub_pol_1
    - sub_pol_2
    - sub_pol_3

- sub_pol_1:
    acl:
    - "- 1-ff00:0:133#0"
    - "+"

- sub_pol_2:
    sequence: "0+ 1-ff00:0:110#0 1-ff00:0:110#0 0+"

- sub_pol_3:
    acl:
    - "- 1-ff00:0:131#0"
    - "- 1-ff00:0:132#0"
    - "- 1-ff00:0:133#0"
    - "+"
    mtu: ">=1000"
```

### Options

The `options` attribute requires a list of anonymous policies. Each policy may have `weight` as an
attribute to specify its importance and may have all other attributes of a policy. Options are
evaluated in the order of their weight. The paths of the policy with the highest weight are used, if
the heighest-weight policy does not match any paths, the next policy is evaluated. When multiple
policies have the same weight, all of their paths are returned. The default for a weight (when it is
omitted) is 0. All paths returned by an option must also match every condition of the top-level
policy (the top-level policy is ANDed to every option).

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
    - "- 1"
    - "+"
- option_1:
    acl:
    - "- 1-ff00:0:133#0"
    - "+"
```
