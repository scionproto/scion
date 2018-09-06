Regenerate the mock using:
```
mockgen -source=interface.go > mock_snetproxy/mock_interface.go
goimports -w -local github.com/scionproto mock_snetproxy/mock_interface.go
mockgen -source=reconnecter.go > mock_snetproxy/mock_reconnecter.go
goimports -w -local github.com/scionproto mock_snetproxy/mock_reconnecter.go
mockgen -source=io.go > mock_snetproxy/mock_io.go
goimports -w -local github.com/scionproto mock_snetproxy/mock_io.go
```

