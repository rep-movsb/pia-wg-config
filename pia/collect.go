package pia

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

const (
	serverListURL     = "https://serverlist.piaservers.net/vpninfo/servers/v4"
	collectUserAgent  = "pia-wg-config"
	defaultCacheTime  = 60 * time.Second
	maxFailureBackoff = 300 * time.Second
	collectTimeLayout = "2006-01-02T15:04:05Z"
)

var maxAgePattern = regexp.MustCompile(`max-age=(\d+)`)

// CollectOptions controls CollectServers. A zero StableRounds, MaxRounds or
// MaxDuration disables that stop condition.
type CollectOptions struct {
	Output       string
	Fresh        bool
	StableRounds int
	MaxRounds    int
	MaxDuration  time.Duration
	Interval     time.Duration
	Timeout      time.Duration
	MaxFailures  int
}

// collectedServers is the output file. LoadServerFile reads the same format.
type collectedServers struct {
	FirstCollected string                      `json:"first_collected"`
	LastUpdated    string                      `json:"last_updated"`
	Regions        map[string]*collectedRegion `json:"regions"`
	ServicePorts   map[string][]int            `json:"service_ports"`
	Snapshots      int                         `json:"snapshots"`
	Source         string                      `json:"source"`
	TotalEndpoints int                         `json:"total_endpoints"`
}

type collectedRegion struct {
	AutoRegion  bool                            `json:"auto_region"`
	Country     string                          `json:"country"`
	DNS         string                          `json:"dns"`
	Geo         bool                            `json:"geo"`
	Name        string                          `json:"name"`
	PortForward bool                            `json:"port_forward"`
	Servers     map[string][]*collectedEndpoint `json:"servers"`
}

type collectedEndpoint struct {
	Cn        string `json:"cn"`
	FirstSeen string `json:"first_seen"`
	IP        string `json:"ip"`
	LastSeen  string `json:"last_seen"`
	TimesSeen int    `json:"times_seen"`
}

// serverSnapshot is one server list response, keeping every service type.
type serverSnapshot struct {
	Groups map[string][]struct {
		Ports []int `json:"ports"`
	} `json:"groups"`
	Regions []struct {
		ID          string              `json:"id"`
		Name        string              `json:"name"`
		Country     string              `json:"country"`
		AutoRegion  bool                `json:"auto_region"`
		DNS         string              `json:"dns"`
		PortForward bool                `json:"port_forward"`
		Geo         bool                `json:"geo"`
		Servers     map[string][]Server `json:"servers"`
	} `json:"regions"`
}

type fetchFunc func(ctx context.Context) ([]byte, http.Header, error)
type sleepFunc func(ctx context.Context, wait time.Duration) error

// CollectServers gathers every PIA endpoint by repeatedly polling the server
// list. Each response names one randomly chosen server per region and service,
// so the full set only emerges across many responses. The CDN caches responses
// for 60 seconds, so requests wait for the cached copy to expire and responses
// already seen are ignored.
//
// The output is rewritten after every new response, so the context can be
// cancelled at any time. An existing output file is merged into unless
// opts.Fresh is set. It returns ctx.Err() if cancelled.
func CollectServers(ctx context.Context, opts CollectOptions) error {
	return collect(ctx, opts, newServerListFetcher(opts.Timeout), sleepContext)
}

func collect(ctx context.Context, opts CollectOptions, fetch fetchFunc, sleep sleepFunc) error {
	state := newCollectedServers()
	if !opts.Fresh {
		var err error
		if state, err = loadCollectedServers(opts.Output); err != nil {
			return err
		}
	}

	var deadline time.Time
	if opts.MaxDuration > 0 {
		deadline = time.Now().Add(opts.MaxDuration)
	}

	seen := map[[sha256.Size]byte]bool{}
	rounds, stable, failures := 0, 0, 0

	for {
		var wait time.Duration
		var snapshot *serverSnapshot
		body, headers, err := fetch(ctx)
		if err == nil {
			snapshot, err = parseServerSnapshot(body)
		}

		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures++
			if failures >= opts.MaxFailures {
				return fmt.Errorf("giving up after %d consecutive failures: %w", failures, err)
			}
			wait = failureBackoff(opts.Interval, failures)
			log.Printf("request failed (%v), retrying in %s", err, wait)
		} else {
			failures = 0
			wait = max(timeUntilRefresh(headers), opts.Interval)
			digest := sha256.Sum256(body)
			if seen[digest] {
				log.Printf("same response as before, retrying in %s", wait)
			} else {
				seen[digest] = true
				rounds++
				added := state.merge(snapshot, time.Now().UTC().Format(collectTimeLayout))
				if err := state.write(opts.Output); err != nil {
					return err
				}
				if added == 0 {
					stable++
				} else {
					stable = 0
				}
				log.Printf("round %d: +%d new, %d total, %d rounds without new endpoints", rounds, added, state.TotalEndpoints, stable)

				if opts.MaxRounds > 0 && rounds >= opts.MaxRounds {
					log.Print("reached --max-rounds")
					return nil
				}
				if opts.StableRounds > 0 && stable >= opts.StableRounds {
					log.Print("reached --stable-rounds")
					return nil
				}
			}
		}

		if !deadline.IsZero() && !time.Now().Add(wait).Before(deadline) {
			log.Print("reached --max-seconds")
			return nil
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func newServerListFetcher(timeout time.Duration) fetchFunc {
	client := &http.Client{Timeout: timeout}
	return func(ctx context.Context) ([]byte, http.Header, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverListURL, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("User-Agent", collectUserAgent)

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("server list request failed: %s", resp.Status)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, err
		}
		return body, resp.Header, nil
	}
}

func sleepContext(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// parseServerSnapshot decodes the JSON document. Decode stops at the end of the
// document, which skips the signature that follows it.
func parseServerSnapshot(body []byte) (*serverSnapshot, error) {
	var snapshot serverSnapshot
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&snapshot); err != nil {
		return nil, errors.Wrap(err, "error parsing server list")
	}
	if snapshot.Regions == nil {
		return nil, errors.New("response has no regions list")
	}
	for _, region := range snapshot.Regions {
		if region.ID == "" {
			return nil, errors.New("response has a region with no id")
		}
		for service, servers := range region.Servers {
			for _, server := range servers {
				if server.IP == "" || server.Cn == "" {
					return nil, fmt.Errorf("response has an incomplete %s server in region %s", service, region.ID)
				}
			}
		}
	}
	return &snapshot, nil
}

// timeUntilRefresh returns how long the CDN will keep serving the copy just
// received.
func timeUntilRefresh(headers http.Header) time.Duration {
	match := maxAgePattern.FindStringSubmatch(headers.Get("Cache-Control"))
	if match == nil {
		return defaultCacheTime
	}
	maxAge, err := strconv.Atoi(match[1])
	if err != nil {
		return defaultCacheTime
	}
	age, err := strconv.Atoi(headers.Get("Age"))
	if err != nil {
		age = 0
	}
	return time.Duration(max(maxAge-age, 0)+1) * time.Second
}

func failureBackoff(interval time.Duration, failures int) time.Duration {
	wait := interval
	for range failures {
		wait *= 2
		if wait >= maxFailureBackoff {
			return maxFailureBackoff
		}
	}
	return min(wait, maxFailureBackoff)
}

func newCollectedServers() *collectedServers {
	return &collectedServers{
		Source:       serverListURL,
		Regions:      map[string]*collectedRegion{},
		ServicePorts: map[string][]int{},
	}
}

// loadCollectedServers loads an earlier run's output, or starts fresh if there
// is none. A file in another format is an error rather than being overwritten.
func loadCollectedServers(path string) (*collectedServers, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return newCollectedServers(), nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "error reading output file")
	}

	state := newCollectedServers()
	state.Regions = nil
	if err := json.Unmarshal(data, state); err != nil {
		return nil, errors.Wrapf(err, "%s is not a collected server list", path)
	}
	if state.Regions == nil {
		return nil, fmt.Errorf("%s is not a collected server list", path)
	}
	log.Printf("merging into existing %s (%d endpoints)", path, state.TotalEndpoints)
	return state, nil
}

// merge adds one response to the state and returns how many endpoints were new.
func (s *collectedServers) merge(snapshot *serverSnapshot, now string) int {
	added := 0
	if s.FirstCollected == "" {
		s.FirstCollected = now
	}
	s.LastUpdated = now
	s.Snapshots++

	for service, groups := range snapshot.Groups {
		var ports []int
		for _, group := range groups {
			ports = append(ports, group.Ports...)
		}
		slices.Sort(ports)
		s.ServicePorts[service] = slices.Compact(ports)
	}

	for _, region := range snapshot.Regions {
		entry := s.Regions[region.ID]
		if entry == nil {
			entry = &collectedRegion{}
			s.Regions[region.ID] = entry
		}
		if entry.Servers == nil {
			entry.Servers = map[string][]*collectedEndpoint{}
		}
		entry.Name = region.Name
		entry.Country = region.Country
		entry.DNS = region.DNS
		entry.PortForward = region.PortForward
		entry.Geo = region.Geo
		entry.AutoRegion = region.AutoRegion

		for service, servers := range region.Servers {
			known := entry.Servers[service]
			index := make(map[Server]*collectedEndpoint, len(known))
			for _, endpoint := range known {
				index[Server{Cn: endpoint.Cn, IP: endpoint.IP}] = endpoint
			}

			for _, server := range servers {
				if endpoint := index[server]; endpoint != nil {
					endpoint.LastSeen = now
					endpoint.TimesSeen++
					continue
				}
				endpoint := &collectedEndpoint{Cn: server.Cn, IP: server.IP, FirstSeen: now, LastSeen: now, TimesSeen: 1}
				known = append(known, endpoint)
				index[server] = endpoint
				added++
			}

			slices.SortFunc(known, func(a, b *collectedEndpoint) int {
				return cmp.Or(cmp.Compare(a.Cn, b.Cn), cmp.Compare(a.IP, b.IP))
			})
			entry.Servers[service] = known
		}
	}

	s.TotalEndpoints = 0
	for _, region := range s.Regions {
		for _, servers := range region.Servers {
			s.TotalEndpoints += len(servers)
		}
	}
	return added
}

// write saves the state atomically so an interrupted run cannot corrupt it.
func (s *collectedServers) write(path string) (err error) {
	file, err := os.CreateTemp(filepath.Dir(path), "*.tmp")
	if err != nil {
		return errors.Wrap(err, "error creating output file")
	}
	defer func() {
		if err != nil {
			os.Remove(file.Name())
		}
	}()

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(s); err != nil {
		file.Close()
		return errors.Wrap(err, "error writing output file")
	}
	if err := file.Close(); err != nil {
		return errors.Wrap(err, "error writing output file")
	}
	return errors.Wrap(os.Rename(file.Name(), path), "error replacing output file")
}
