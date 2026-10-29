// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endhost

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/endhost/token"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/trust"
)

type ConnectOption func(*connectOptions)
type connectOptions struct {
	// disable tls for all requests
	insecure bool
	// loads trcs from provided folder
	trcDir          string
	localIA         addr.IA
	localIASelector func(*Underlays) addr.IA
	// tls client certificate, might be required for drkey requests
	tlsCertificate *tls.Certificate
	tokenProvider  token.Provider
	localIP        net.IP
}

// Disables all TLS verifications. Implies allow insecure.
func WithInsecureConnection() ConnectOption {
	return func(o *connectOptions) {
		o.insecure = true
	}
}

// Loads all TRCs from the provided folder.
func WithCertsDir(dir string) ConnectOption {
	return func(o *connectOptions) {
		o.trcDir = dir
	}
}

// Defines the local IA to use. If the provided IA is not valid,
// an error is thrown.
func WithLocalIA(ia addr.IA) ConnectOption {
	return func(o *connectOptions) {
		o.localIA = ia
	}
}

// Alternative way to choose the local IA. Cannot be used together with the
// WithLocalIA option. The provided function is not allowed to modify
// the provided Underlays.
func WithLocalIASelector(f func(*Underlays) addr.IA) ConnectOption {
	return func(o *connectOptions) {
		o.localIASelector = f
	}
}

// If provided, calls the token provider to retrieve jwt tokens
func WithTokenProvider(provider token.Provider) ConnectOption {
	return func(o *connectOptions) {
		o.tokenProvider = provider
	}
}

// Sets the local IP when dialing.
func WithLocalIP(ip net.IP) ConnectOption {
	return func(o *connectOptions) {
		o.localIP = ip
	}
}

// If provided, the underlying http client will provide this certificate for mTLS
// if requested by the server.
func WithClientCert(certs []*x509.Certificate, privKey crypto.PrivateKey) ConnectOption {
	return func(o *connectOptions) {
		var chain [][]byte
		for _, c := range certs {
			chain = append(chain, c.Raw)
		}
		o.tlsCertificate = &tls.Certificate{
			Certificate: chain,
			PrivateKey:  privKey,
		}
	}
}

type authTransport struct {
	tokenProvider token.Provider
	base          http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if t.tokenProvider != nil {
		token, err := t.tokenProvider.Token(req.Context())
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return t.base.RoundTrip(req)
}

func (c *Connector) setupWebPKI(ctx context.Context, clientCerts []tls.Certificate, dialContext func(ctx context.Context, network string, addr string) (net.Conn, error),
	options *connectOptions) error {
	log.Debug("endhostAPI try connection using webPKI")
	var err error
	c.httpClient = &http.Client{
		Transport: &authTransport{
			tokenProvider: c.tokenProvider,
			base: &http.Transport{
				DialContext: dialContext,
				TLSClientConfig: &tls.Config{
					Certificates: clientCerts,
				},
			},
		},
	}
	c.UnderlayService = NewUnderlayService(c.api, c.httpClient)
	c.Topology, err = c.loadTopology(ctx, options.localIA, options.localIASelector)
	if err != nil {
		return err
	}
	c.TrustService = NewTrustService(c.api, c.trustDB, c.httpClient)
	c.PathService = NewPathService(c.api, c.Topology, c.httpClient, c.Topology.LocalIA, c.TrustService)
	c.DRKeyService = NewDRKeyService(c.api, c.httpClient)
	return nil
}
func (c *Connector) setupSCIONPKI(ctx context.Context, clientCerts []tls.Certificate, dialContext func(ctx context.Context, network string, addr string) (net.Conn, error),
	options *connectOptions) error {
	log.Debug("endhostAPI try connection using scion PKI")
	u, err := url.Parse(c.api)
	if err != nil {
		return err
	}
	endhostApiAddr, err := net.ResolveTCPAddr("tcp", u.Host)
	if err != nil {
		return err
	}
	localIA := options.localIA
	if options.trcDir == "" {
		// We want to use tls but have no local trust root configuration
		// so we can try to retrieve the local ISD TRC from the endhost api.
		// But since we cannot use a TRC to verify the connection to retrieve the TRC,
		// we cannot ensure that a valid TRC is returned.
		log.Debug("setting up endhost-api client by fetching TRC from endhost API server")
		c.httpClient = &http.Client{
			Transport: &authTransport{
				tokenProvider: c.tokenProvider,
				base: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						Certificates:       clientCerts,
					},
					DialContext: dialContext,
				},
			},
		}
		c.UnderlayService = NewUnderlayService(c.api, c.httpClient)
		c.Topology, err = c.loadTopology(ctx, options.localIA, options.localIASelector)
		if err != nil {
			return err
		}
		localIA = c.Topology.LocalIA
		c.TrustService = NewTrustService(c.api, c.trustDB, c.httpClient)
		_, err := c.TrustService.GetTRC(ctx, uint32(localIA.ISD()), 0, 0)
		if err != nil {
			return err
		}
		c.DRKeyService = NewDRKeyService(c.api, c.httpClient)
	}
	// Now we should have a TRC for the local ISD in the trust store and can
	// initialize the connector properly.
	tlsVerifier := trust.NewTLSCryptoVerifier(c.trustDB)

	if localIA.IsZero() {
		// since localIA is not specified, we have to query for underlays without being able to
		// use tlsVerifier.VerifyConnection since this would require setting ServerName
		c.httpClient = &http.Client{
			Transport: &authTransport{
				tokenProvider: c.tokenProvider,
				base: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify:    true,
						VerifyPeerCertificate: tlsVerifier.VerifyServerCertificate,
						Certificates:          clientCerts,
					},
					DialContext: dialContext,
				},
			},
		}
		c.UnderlayService = NewUnderlayService(c.api, c.httpClient)
		c.Topology, err = c.loadTopology(ctx, options.localIA, options.localIASelector)
		if err != nil {
			return err
		}
		// now we know the local IA, so we can modify the tls configuration
		c.httpClient = &http.Client{
			Transport: &authTransport{
				tokenProvider: c.tokenProvider,
				base: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify:    true,
						VerifyConnection:      tlsVerifier.VerifyConnection,
						VerifyPeerCertificate: tlsVerifier.VerifyServerCertificate,
						Certificates:          clientCerts,
						ServerName: fmt.Sprintf("%s,%s", c.Topology.LocalIA,
							endhostApiAddr.IP.String()),
					},
					DialContext: dialContext,
				},
			},
		}
	} else {
		c.httpClient = &http.Client{
			Transport: &authTransport{
				tokenProvider: c.tokenProvider,
				base: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify:    true,
						VerifyConnection:      tlsVerifier.VerifyConnection,
						VerifyPeerCertificate: tlsVerifier.VerifyServerCertificate,
						Certificates:          clientCerts,
						ServerName: fmt.Sprintf("%s,%s", localIA,
							endhostApiAddr.IP.String()),
					},
					DialContext: dialContext,
				},
			},
		}
		c.UnderlayService = NewUnderlayService(c.api, c.httpClient)
		c.Topology, err = c.loadTopology(ctx, options.localIA, options.localIASelector)
		if err != nil {
			return err
		}
	}
	c.TrustService = NewTrustService(c.api, c.trustDB, c.httpClient)
	c.PathService = NewPathService(c.api, c.Topology, c.httpClient, c.Topology.LocalIA, c.TrustService)
	c.DRKeyService = NewDRKeyService(c.api, c.httpClient)
	return nil
}

// NewConnector initializes the endhost API connector using the provided api URL.
// When no TRCs are provided, the connector will try to fetch the local ISD TRC from the
// endhost API. However, since the client does not have the trust material to verify the connection
// to the endhost-api server, a man-in-the-middle attacks could theoretically happen.
func NewConnector(ctx context.Context, api string, opts ...ConnectOption) (*Connector, error) {
	options := &connectOptions{}
	for _, opt := range opts {
		opt(options)
	}

	c := &Connector{
		api:           api,
		tokenProvider: options.tokenProvider,
	}
	clientCerts := []tls.Certificate{}
	if options.tlsCertificate != nil {
		clientCerts = append(clientCerts, *options.tlsCertificate)
	}
	var err error
	c.trustDB, err = storage.NewInMemoryTrustStorage()
	if err != nil {
		return nil, err
	}
	if options.trcDir != "" {
		// Load TRC from local folder
		trcLoader := trust.TRCLoader{
			Dir: options.trcDir,
			DB:  c.trustDB,
		}
		_, err = trcLoader.Load(ctx)
		if err != nil {
			return nil, err
		}
	}
	var dialContext func(ctx context.Context, network string, addr string) (net.Conn, error)
	if options.localIP != nil {
		dialer := net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP: options.localIP,
			},
		}
		dialContext = dialer.DialContext
	}

	if options.insecure {
		log.Debug("setting up endhost-api client in insecure mode")
		// accept any TLS certificate or non-tls connection
		c.httpClient = &http.Client{
			Transport: &authTransport{
				tokenProvider: c.tokenProvider,
				base: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						Certificates:       clientCerts,
					},
					DialContext: dialContext,
				},
			},
		}
		c.UnderlayService = NewUnderlayService(c.api, c.httpClient)
		c.Topology, err = c.loadTopology(ctx, options.localIA, options.localIASelector)
		if err != nil {
			return nil, err
		}
		c.TrustService = NewTrustService(c.api, c.trustDB, c.httpClient)
		c.PathService = NewPathService(c.api, c.Topology, c.httpClient, c.Topology.LocalIA, c.TrustService)
		c.DRKeyService = NewDRKeyService(c.api, c.httpClient)
		return c, nil
	}
	// test whether endhost API server uses certificate signed by WebPKI CA
	// If an error occurs, try again using SCION PKI
	// If both fail, return both errors
	err = c.setupWebPKI(ctx, clientCerts, dialContext, options)
	if err != nil {
		err2 := c.setupSCIONPKI(ctx, clientCerts, dialContext, options)
		if err2 != nil {
			return nil, serrors.Join(err2, err)
		}
	}
	return c, nil
}

type Connector struct {
	api             string
	httpClient      *http.Client
	trustDB         storage.TrustDB
	Topology        snet.Topology
	UnderlayService *UnderlayService
	PathService     *PathService
	TrustService    *TrustService
	DRKeyService    *DRKeyService
	// cached values
	interfaces    map[uint16]netip.AddrPort
	tokenProvider token.Provider
}

// loadTopology is called from NewConnector and uses the underlay service to determine the
// available underlays, the local IA and its interfaces and populates a snet.Topology struct.
func (c *Connector) loadTopology(ctx context.Context, localIA addr.IA,
	iaSelector func(*Underlays) addr.IA) (snet.Topology, error) {

	topo := snet.Topology{}
	var allUnderlays *Underlays
	var err error
	// 1. determine all possible underlays
	if localIA.IsZero() {
		allUnderlays, err = c.UnderlayService.ListUnderlays(ctx, nil)
	} else {
		allUnderlays, err = c.UnderlayService.ListUnderlays(ctx, &localIA)
	}
	if err != nil {
		return topo, err
	}
	// 2. determine all possible local IAs
	allPossibleLocalIAs := []addr.IA{}
	iaPortRange := make(map[addr.IA]snet.TopologyPortRange)
	snapIAs := make(map[addr.IA]string)
	if allUnderlays.Udp != nil {
		for _, router := range allUnderlays.Udp.Routers {
			ia := addr.IA(router.IsdAs)
			_, found := iaPortRange[ia]
			if !found {
				allPossibleLocalIAs = append(allPossibleLocalIAs, ia)
				iaPortRange[ia] = snet.TopologyPortRange{
					Start: uint16(router.DispatchedPortStart),
					End:   uint16(router.DispatchedPortEnd),
				}
			}
		}
	}
	if allUnderlays.Snap != nil {
		for _, s := range allUnderlays.Snap.Snaps {
			snapControl := s.Address
			for _, ia := range s.IsdASes {
				if !slices.Contains(allPossibleLocalIAs, ia) {
					allPossibleLocalIAs = append(allPossibleLocalIAs, ia)
					snapIAs[ia] = snapControl
				}
			}
		}
	}
	if len(allPossibleLocalIAs) == 0 {
		return topo, serrors.New("No local AS found")
	}
	// 3. let the callee choose which IA the local IA should be
	if localIA.IsZero() {
		if iaSelector != nil {
			selectedIA := iaSelector(allUnderlays)
			if !slices.Contains(allPossibleLocalIAs, selectedIA) {
				return topo, serrors.New("Invalid IA selected")
			}
			localIA = selectedIA
		} else {
			localIA = allPossibleLocalIAs[0]
		}
	}
	portRange, found := iaPortRange[localIA]
	if found {
		// it should be found if localIA has an UDP underlay. If it has
		// only a SNAP underlay, the port range is unknown.
		topo.PortRange = snet.TopologyPortRange{
			Start: portRange.Start,
			End:   portRange.End,
		}
	}
	topo.LocalIA = localIA

	c.interfaces = make(map[uint16]netip.AddrPort)
	topo.Interface = func(u uint16) (netip.AddrPort, bool) {
		addr, ok := c.interfaces[u]
		return addr, ok
	}
	// 4. populate the interfaces of the UDP underlay of the local IA
	if allUnderlays.Udp != nil {
		for _, router := range allUnderlays.Udp.Routers {
			if localIA != addr.IA(router.IsdAs) {
				// skip routers that do not belong to selected local IA
				continue
			}
			addr, err := netip.ParseAddrPort(router.Address)
			if err != nil {
				return topo, err
			}
			for _, inf := range router.Interfaces {
				c.interfaces[uint16(inf)] = addr
			}
		}
	}
	// 5. prepare the SNAP configuration if the local IA supports SNAP
	if _, found := snapIAs[localIA]; found {
		// TODO: implementation of the SNAP client is a separate PR
	}
	return topo, nil
}

func (c *Connector) Close() error {
	var err error
	if c.PathService != nil {
		err = c.PathService.Close()
	}
	if c.trustDB != nil {
		err2 := c.trustDB.Close()
		if err2 != nil {
			err = serrors.Join(err2, err)
		}
	}
	return err
}
