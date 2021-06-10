The routing policy file contains the configuration which IP prefixes are
advertised, accepted, and rejected.

A routing policy consists of a list of rules. Each rule consists of an action
and three matchers. Optionally, a rule can have a comment.

Policies are defined in plain text. Each line represents a rule. Each rule
consists of four whitespace separated columns. The optional comment is
appended at the end of the line and needs to start with a '#'. ::

  accept     1-ff00:0:110   1-ff00:0:112  10.0.1.0/24,10.0.2.0/24  # Accept from AS 110.
  accept     2-0            1-ff00:0:112  10.0.3.0/24              # Accept from ISD 2.
  reject     !1-ff00:0:110  1-ff00:0:112  10.0.0.0/8               # Reject unless AS 110.
  advertise  1-ff00:0:112   1-ff00:0:110  10.0.9.0/8               # 1-ff00:0:112 advertises 10.0.9.0/8 to 1-ff00:0:110.

The first column represents the action. Currently, we support: ::

  accept    <a> <b> <prefixes>: <b> accepts the IP prefixes <prefixes> from <a>.
  reject    <a> <b> <prefixes>: <b> rejects the IP prefixes <prefixes> from <a>.
  advertise <a> <b> <prefixes>: <a> advertises the IP prefixes <prefixes> to <b>.

The remaining three columns define the matchers of a rule. The second and
third column are ISD-AS matchers, the forth column is a prefix matcher.

The second column matches the 'from' ISD-AS. The third column the 'to'
ISD-AS. ISD-AS matchers support wildcards and negation: ::

  1-ff00:0:110   Matches for 1-ff00:0:110 only.
  0-ff00:0:110   Matches for all ASes with AS number ff00:0:110.
  1-0            Matches for all ASes in ISD 1.
  0-0            Matches for all ASes.

  !0-ff00:0:110  Matches for all ASes except the ones with AS number 'ff00:0:110'.
  !1-ff00:0:110  Matches for all ASes except 1-ff00:0:110.
  !1-0           Matches for all ASes not in ISD 1.

Network prefix matcher consist of a list of IP prefixes to match. The list is
comma-separated. A prefix matches, if it is in the subset of the union of the
IP prefixes in the list. The network prefix matcher can also be negated. The
negation applies to the entire list. A prefix matches in the negated case, if
it is not a subset of the union of the prefix list. ::

  10.0.1.0/24,10.0.2.0/24    Matches all IP prefixes that are a subset of 10.0.1.0/24 or
                             10.0.2.0/24. It also matches 10.0.1.0/24 and 10.0.2.0/24.
  !10.0.1.0/24,10.0.2.0/24   Matches all IP prefixes that are not a subset of 10.0.1.0/24 and
                             not a subset of 10.0.2.0/24.

Default Routing Policy
----------------------

The routing policy file is optional. If no routing policy is explicitly defined,
the gateway uses a default policy equivalent to ::

  reject 0-0 0-0 0.0.0.0/0,::/0

i.e., it rejects all IP prefixes advertised by any remote. Additionally, no local
IP prefixes are advertised, because there is no explicit ``advertise`` directive.
