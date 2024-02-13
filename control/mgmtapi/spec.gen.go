// Package mgmtapi provides primitives to interact with the openapi HTTP API.
//
// Code generated by unknown module path version unknown version DO NOT EDIT.
package mgmtapi

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
