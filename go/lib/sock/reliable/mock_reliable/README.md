Regenerate the mock using:
```
mockgen -source=reconnect.go > mock_reliable/mock_reliable.go
goimports -w -local github.com/scionproto mock_reliable/mock_reliable.go
```
