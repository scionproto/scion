# Gobra specs

This directory contains the formal specification of a small part of the
Go standard library (in [`./stdlib-specs`](./stdlib-specs)) required to
verify the annotated files in the SCION codebase. In addition, we provide
a verified Gobra package in [`./utils`](./utils) that contains useful
definitions that are used in the verified packages of SCION.

## Contributing

It is expected that we will need a formal specification for more parts
of the Go standard library as we progress in verifying more code in the
SCION repository. To do so, one may add the type declarations and
signatures of unspecified functions and methods (_without the bodies_),
together with their contracts (i.e., pre- and postconditions), to the
corresponding package specification in directory
[`./stdlib-specs`](./stdlib-specs).

Given that the specification of the standard library is not verified by
Gobra itself, it is possible to introduce errors when writing the
specification for these methods. Thus, any extensions to the specification
require extreme care from the author of the extensions and from code reviewers.
