gen:
	oapi-codegen -package api -generate spec control.yml > ../go/pkg/cs/api/spec.gen.go
	oapi-codegen -package api -generate types control.yml > ../go/pkg/cs/api/types.gen.go
	oapi-codegen -package api -generate chi-server control.yml > ../go/pkg/cs/api/server.gen.go
	go fmt ../go/pkg/cs/api/
