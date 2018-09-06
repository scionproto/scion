Regenerate the mock using:

```sh
mockgen -source=go/lib/snet/snetproxy/interface.go > go/lib/snet/snetproxy/mock_snetproxy/mock_interface.go
mockgen -source=go/lib/snet/snetproxy/reconnecter.go > go/lib/snet/snetproxy/mock_snetproxy/mock_reconnecter.go
mockgen -source=go/lib/snet/snetproxy/io.go > go/lib/snet/snetproxy/mock_snetproxy/mock_io.go
```
