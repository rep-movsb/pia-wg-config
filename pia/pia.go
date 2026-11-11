package pia

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/benburkert/dns"
	"github.com/pkg/errors"
)

type PIAWgClient interface {
	GetToken() (string, error)
	AddKey(token, publickey string) (AddKeyResult, error)
}

type Region string
type ServerList map[Region][]Server

type PIAClient struct {
	region           string
	wireguardServers ServerList
	username         string
	password         string
	verbose          bool

	// mu guards caCert and token, which are shared by concurrent requests.
	mu     sync.Mutex
	caCert []byte
	token  string
}

type piaServerList struct {
	Regions []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Country     string `json:"country"`
		AutoRegion  bool   `json:"auto_region"`
		DNS         string `json:"dns"`
		PortForward bool   `json:"port_forward"`
		Geo         bool   `json:"geo"`
		Servers     struct {
			Meta []Server `json:"meta"`
			Wg   []Server `json:"wg"`
		} `json:"servers"`
	} `json:"regions"`
}

type AddKeyResult struct {
	Status     string   `json:"status"`
	ServerKey  string   `json:"server_key"`
	ServerPort int      `json:"server_port"`
	ServerIP   string   `json:"server_ip"`
	ServerVip  string   `json:"server_vip"`
	PeerIP     string   `json:"peer_ip"`
	PeerPubkey string   `json:"peer_pubkey"`
	DNSServers []string `json:"dns_servers"`
}

type Server struct {
	Cn string
	IP string
}

// NewPIAClient creates a new PIA client for with the list of servers populated
func NewPIAClient(username, password, region string, verbose bool) (*PIAClient, error) {
	piaClient := PIAClient{
		username: username,
		password: password,
		region:   region,
		verbose:  verbose,
	}

	// Get list of servers
	serverList, err := piaClient.getServerList()
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch server list from PIA")
	}

	// Set servers
	piaClient.wireguardServers = piaClient.generateWireguardServerList(serverList)

	// Validate region exists
	if _, exists := piaClient.wireguardServers[Region(region)]; !exists {
		availableRegions := make([]string, 0, len(piaClient.wireguardServers))
		for r := range piaClient.wireguardServers {
			availableRegions = append(availableRegions, string(r))
		}
		return nil, fmt.Errorf("region '%s' not found. Available regions: %v. Use 'pia-wg-config regions' to see all available regions", region, availableRegions[:5]) // Show first 5 as example
	}

	return &piaClient, nil
}

// NewPIAServerClient creates a PIA client that does not fetch the server list.
// Use ForServer to target servers that came from elsewhere, such as a file.
func NewPIAServerClient(username, password string, verbose bool) *PIAClient {
	return &PIAClient{
		username: username,
		password: password,
		verbose:  verbose,
	}
}

// serverClient is a PIAClient whose AddKey always targets one server.
type serverClient struct {
	*PIAClient
	server Server
}

func (c *serverClient) AddKey(token, publickey string) (AddKeyResult, error) {
	return c.addKeyToServer(token, publickey, c.server)
}

// ForServer returns a client whose AddKey targets the given server. It shares
// the token and CA certificate of p, so one login covers any number of servers.
func (p *PIAClient) ForServer(server Server) PIAWgClient {
	return &serverClient{PIAClient: p, server: server}
}

// tokenURL is PIA's central token API (the same endpoint used by PIA's
// manual-connections scripts). Regional metadata servers no longer serve
// /authv3/generateToken reliably (issues #12, #17).
const tokenURL = "https://www.privateinternetaccess.com/api/client/v2/token"

// GetToken
func (p *PIAClient) GetToken() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.token != "" {
		return p.token, nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(tokenURL, url.Values{
		"username": {p.username},
		"password": {p.password},
	})
	if err != nil {
		return "", errors.Wrap(err, "error executing request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %s", resp.Status)
	}
	// Parse response
	var tokenResp struct {
		Token string `json:"token"`
	}

	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tokenResp)
	if err != nil {
		return "", errors.Wrap(err, "error decoding token response")
	}

	if p.verbose {
		log.Print("Got token")
	}

	p.token = tokenResp.Token
	return tokenResp.Token, nil
}

// GetAvailableRegions returns all available regions
func (p *PIAClient) GetAvailableRegions() (map[Region]string, error) {
	serverList, err := p.getServerList()
	if err != nil {
		return nil, err
	}

	regions := make(map[Region]string)
	for _, r := range serverList.Regions {
		regions[Region(r.ID)] = r.Name
	}

	return regions, nil
}

// AddKey
func (p *PIAClient) AddKey(token, publickey string) (AddKeyResult, error) {
	return p.addKeyToServer(token, publickey, p.getWireguardServerForRegion())
}

func (p *PIAClient) addKeyToServer(token, publickey string, server Server) (AddKeyResult, error) {
	var addKeyResp AddKeyResult

	// Build http request
	requestURL := fmt.Sprintf("https://%v:1337/addKey?pt=%v&pubkey=%v", server.Cn, url.QueryEscape(token), url.QueryEscape(publickey))

	// Send request
	resp, err := p.executePIARequest(server, requestURL, token)
	if err != nil {
		return addKeyResp, errors.Wrap(err, "error executing request")
	}
	defer resp.Body.Close()

	// Parse response
	err = json.NewDecoder(resp.Body).Decode(&addKeyResp)
	if err != nil {
		return addKeyResp, errors.Wrap(err, "error decoding add key response")
	}

	if addKeyResp.Status != "OK" {
		return addKeyResp, fmt.Errorf("add key rejected with status %q", addKeyResp.Status)
	}

	return addKeyResp, nil
}

func (p *PIAClient) getWireguardServerForRegion() Server {
	if p.verbose {
		log.Print("Getting wireguard server for region: ", p.region)
	}
	servers := p.wireguardServers[Region(p.region)]
	if len(servers) == 0 {
		log.Fatalf("No Wireguard servers available for region: %s", p.region)
	}
	return servers[0]
}

// getSeverList returns a list of servers from the PIA API
func (p *PIAClient) getServerList() (piaServerList, error) {
	var serverList piaServerList

	resp, err := http.Get(serverListURL)
	if err != nil {
		return piaServerList{}, err
	}

	// Strip the base64 garbage
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return piaServerList{}, err
	}
	respString := string(respBytes)
	lastBracketInd := strings.LastIndex(respString, "}")
	safeJSON := respString[:lastBracketInd+1]

	// Parse the JSON
	err = json.Unmarshal([]byte(safeJSON), &serverList)
	if err != nil {
		return piaServerList{}, err
	}

	// Return list of servers
	return serverList, nil
}

// generateWireguardServerList
func (p *PIAClient) generateWireguardServerList(list piaServerList) ServerList {
	servers := ServerList{}

	for _, r := range list.Regions {
		for _, server := range r.Servers.Wg {
			servers[Region(r.ID)] = append(servers[Region(r.ID)], Server{
				Cn: server.Cn,
				IP: server.IP,
			})
		}
	}

	return servers
}

func (p *PIAClient) executePIARequest(server Server, requestURL, token string) (*http.Response, error) {
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}

	// Set header to JSON
	req.Header.Set("Content-Type", "application/json")

	// Set basic auth
	if token == "" {
		req.SetBasicAuth(p.username, p.password)
	}

	// Add certificate to shared pool
	caCert, err := p.downloadPIACertificate()
	if err != nil {
		return nil, errors.Wrap(err, "error downloading ca certificate")
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create DNS resolver for PIA addresses
	zone := &dns.Zone{
		Origin: "",
		TTL:    5 * time.Minute,
		RRs: dns.RRSet{
			server.Cn: {
				dns.TypeA: []dns.Record{
					&dns.A{A: net.ParseIP(server.IP)},
				},
			},
		},
	}
	mux := new(dns.ResolveMux)
	mux.Handle(dns.TypeANY, zone.Origin, zone)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: (&dns.Client{
			Resolver: mux,
		}).Dial,
	}

	// Set custom DNS server
	dialer := &net.Dialer{
		Resolver: resolver,
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	// Each request gets its own transport, so keep-alives would leak a
	// connection per server during batch generation.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
			DialContext:       dialContext,
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		// url.Error includes the full URL, and the URL contains the token.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return nil, urlErr.Err
		}
		return nil, err
	}

	// Return error if status code is not 200
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("status code %v", resp.StatusCode)
	}

	return resp, nil
}

// downloadPIACertificate returns the PIA certificate, downloading it once
func (p *PIAClient) downloadPIACertificate() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// caCert already loaded
	if len(p.caCert) > 0 {
		return p.caCert, nil
	}

	// Download certificate
	resp, err := http.Get("https://raw.githubusercontent.com/pia-foss/desktop/master/daemon/res/ca/rsa_4096.crt")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse certificate
	p.caCert, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return p.caCert, nil
}
