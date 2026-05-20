# Hummingbird QUIC Acceptance Test

This acceptance test verifies a QUIC handshake and one stream round trip from
AS `1-ff00:0:112` to AS `1-ff00:0:111` over a Hummingbird reservation path in
the tiny topology.

Run it with:

```bash
bazel test --test_output=streamed --cache_test_results=no //acceptance/squic_hummingbird:test
```
