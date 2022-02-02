// Package api provides primitives to interact with the openapi HTTP API.
//
// Code generated by unknown module path version unknown version DO NOT EDIT.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
)

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// GetCertificates request
	GetCertificates(ctx context.Context, params *GetCertificatesParams, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetCertificate request
	GetCertificate(ctx context.Context, chainId ChainID, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetCertificateBlob request
	GetCertificateBlob(ctx context.Context, chainId ChainID, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetTrcs request
	GetTrcs(ctx context.Context, params *GetTrcsParams, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetTrc request
	GetTrc(ctx context.Context, isd int, base int, serial int, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetTrcBlob request
	GetTrcBlob(ctx context.Context, isd int, base int, serial int, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) GetCertificates(ctx context.Context, params *GetCertificatesParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetCertificatesRequest(c.Server, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetCertificate(ctx context.Context, chainId ChainID, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetCertificateRequest(c.Server, chainId)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetCertificateBlob(ctx context.Context, chainId ChainID, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetCertificateBlobRequest(c.Server, chainId)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetTrcs(ctx context.Context, params *GetTrcsParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetTrcsRequest(c.Server, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetTrc(ctx context.Context, isd int, base int, serial int, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetTrcRequest(c.Server, isd, base, serial)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetTrcBlob(ctx context.Context, isd int, base int, serial int, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetTrcBlobRequest(c.Server, isd, base, serial)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewGetCertificatesRequest generates requests for GetCertificates
func NewGetCertificatesRequest(server string, params *GetCertificatesParams) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/certificates")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	queryValues := queryURL.Query()

	if params.IsdAs != nil {

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "isd_as", runtime.ParamLocationQuery, *params.IsdAs); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

	}

	if params.ValidAt != nil {

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "valid_at", runtime.ParamLocationQuery, *params.ValidAt); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

	}

	if params.All != nil {

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "all", runtime.ParamLocationQuery, *params.All); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

	}

	queryURL.RawQuery = queryValues.Encode()

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetCertificateRequest generates requests for GetCertificate
func NewGetCertificateRequest(server string, chainId ChainID) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "chain-id", runtime.ParamLocationPath, chainId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/certificates/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetCertificateBlobRequest generates requests for GetCertificateBlob
func NewGetCertificateBlobRequest(server string, chainId ChainID) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "chain-id", runtime.ParamLocationPath, chainId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/certificates/%s/blob", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetTrcsRequest generates requests for GetTrcs
func NewGetTrcsRequest(server string, params *GetTrcsParams) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/trcs")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	queryValues := queryURL.Query()

	if params.Isd != nil {

		if queryFrag, err := runtime.StyleParamWithLocation("form", false, "isd", runtime.ParamLocationQuery, *params.Isd); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

	}

	if params.All != nil {

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "all", runtime.ParamLocationQuery, *params.All); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

	}

	queryURL.RawQuery = queryValues.Encode()

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetTrcRequest generates requests for GetTrc
func NewGetTrcRequest(server string, isd int, base int, serial int) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "isd", runtime.ParamLocationPath, isd)
	if err != nil {
		return nil, err
	}

	var pathParam1 string

	pathParam1, err = runtime.StyleParamWithLocation("simple", false, "base", runtime.ParamLocationPath, base)
	if err != nil {
		return nil, err
	}

	var pathParam2 string

	pathParam2, err = runtime.StyleParamWithLocation("simple", false, "serial", runtime.ParamLocationPath, serial)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/trcs/isd%s-b%s-s%s", pathParam0, pathParam1, pathParam2)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetTrcBlobRequest generates requests for GetTrcBlob
func NewGetTrcBlobRequest(server string, isd int, base int, serial int) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "isd", runtime.ParamLocationPath, isd)
	if err != nil {
		return nil, err
	}

	var pathParam1 string

	pathParam1, err = runtime.StyleParamWithLocation("simple", false, "base", runtime.ParamLocationPath, base)
	if err != nil {
		return nil, err
	}

	var pathParam2 string

	pathParam2, err = runtime.StyleParamWithLocation("simple", false, "serial", runtime.ParamLocationPath, serial)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/trcs/isd%s-b%s-s%s/blob", pathParam0, pathParam1, pathParam2)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// GetCertificates request
	GetCertificatesWithResponse(ctx context.Context, params *GetCertificatesParams, reqEditors ...RequestEditorFn) (*GetCertificatesResponse, error)

	// GetCertificate request
	GetCertificateWithResponse(ctx context.Context, chainId ChainID, reqEditors ...RequestEditorFn) (*GetCertificateResponse, error)

	// GetCertificateBlob request
	GetCertificateBlobWithResponse(ctx context.Context, chainId ChainID, reqEditors ...RequestEditorFn) (*GetCertificateBlobResponse, error)

	// GetTrcs request
	GetTrcsWithResponse(ctx context.Context, params *GetTrcsParams, reqEditors ...RequestEditorFn) (*GetTrcsResponse, error)

	// GetTrc request
	GetTrcWithResponse(ctx context.Context, isd int, base int, serial int, reqEditors ...RequestEditorFn) (*GetTrcResponse, error)

	// GetTrcBlob request
	GetTrcBlobWithResponse(ctx context.Context, isd int, base int, serial int, reqEditors ...RequestEditorFn) (*GetTrcBlobResponse, error)
}

type GetCertificatesResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *[]ChainBrief
}

// Status returns HTTPResponse.Status
func (r GetCertificatesResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetCertificatesResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetCertificateResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *Chain
}

// Status returns HTTPResponse.Status
func (r GetCertificateResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetCertificateResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetCertificateBlobResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r GetCertificateBlobResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetCertificateBlobResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetTrcsResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *[]TRCBrief
	JSON400      *StandardError
}

// Status returns HTTPResponse.Status
func (r GetTrcsResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetTrcsResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetTrcResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *TRC
	JSON400      *StandardError
}

// Status returns HTTPResponse.Status
func (r GetTrcResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetTrcResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetTrcBlobResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON400      *StandardError
}

// Status returns HTTPResponse.Status
func (r GetTrcBlobResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetTrcBlobResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// GetCertificatesWithResponse request returning *GetCertificatesResponse
func (c *ClientWithResponses) GetCertificatesWithResponse(ctx context.Context, params *GetCertificatesParams, reqEditors ...RequestEditorFn) (*GetCertificatesResponse, error) {
	rsp, err := c.GetCertificates(ctx, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetCertificatesResponse(rsp)
}

// GetCertificateWithResponse request returning *GetCertificateResponse
func (c *ClientWithResponses) GetCertificateWithResponse(ctx context.Context, chainId ChainID, reqEditors ...RequestEditorFn) (*GetCertificateResponse, error) {
	rsp, err := c.GetCertificate(ctx, chainId, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetCertificateResponse(rsp)
}

// GetCertificateBlobWithResponse request returning *GetCertificateBlobResponse
func (c *ClientWithResponses) GetCertificateBlobWithResponse(ctx context.Context, chainId ChainID, reqEditors ...RequestEditorFn) (*GetCertificateBlobResponse, error) {
	rsp, err := c.GetCertificateBlob(ctx, chainId, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetCertificateBlobResponse(rsp)
}

// GetTrcsWithResponse request returning *GetTrcsResponse
func (c *ClientWithResponses) GetTrcsWithResponse(ctx context.Context, params *GetTrcsParams, reqEditors ...RequestEditorFn) (*GetTrcsResponse, error) {
	rsp, err := c.GetTrcs(ctx, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetTrcsResponse(rsp)
}

// GetTrcWithResponse request returning *GetTrcResponse
func (c *ClientWithResponses) GetTrcWithResponse(ctx context.Context, isd int, base int, serial int, reqEditors ...RequestEditorFn) (*GetTrcResponse, error) {
	rsp, err := c.GetTrc(ctx, isd, base, serial, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetTrcResponse(rsp)
}

// GetTrcBlobWithResponse request returning *GetTrcBlobResponse
func (c *ClientWithResponses) GetTrcBlobWithResponse(ctx context.Context, isd int, base int, serial int, reqEditors ...RequestEditorFn) (*GetTrcBlobResponse, error) {
	rsp, err := c.GetTrcBlob(ctx, isd, base, serial, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetTrcBlobResponse(rsp)
}

// ParseGetCertificatesResponse parses an HTTP response from a GetCertificatesWithResponse call
func ParseGetCertificatesResponse(rsp *http.Response) (*GetCertificatesResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetCertificatesResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest []ChainBrief
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParseGetCertificateResponse parses an HTTP response from a GetCertificateWithResponse call
func ParseGetCertificateResponse(rsp *http.Response) (*GetCertificateResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetCertificateResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest Chain
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParseGetCertificateBlobResponse parses an HTTP response from a GetCertificateBlobWithResponse call
func ParseGetCertificateBlobResponse(rsp *http.Response) (*GetCertificateBlobResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetCertificateBlobResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseGetTrcsResponse parses an HTTP response from a GetTrcsWithResponse call
func ParseGetTrcsResponse(rsp *http.Response) (*GetTrcsResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetTrcsResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest []TRCBrief
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest StandardError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	}

	return response, nil
}

// ParseGetTrcResponse parses an HTTP response from a GetTrcWithResponse call
func ParseGetTrcResponse(rsp *http.Response) (*GetTrcResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetTrcResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest TRC
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest StandardError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	}

	return response, nil
}

// ParseGetTrcBlobResponse parses an HTTP response from a GetTrcBlobWithResponse call
func ParseGetTrcBlobResponse(rsp *http.Response) (*GetTrcBlobResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetTrcBlobResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest StandardError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	}

	return response, nil
}
