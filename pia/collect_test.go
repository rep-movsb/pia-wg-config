package pia

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// serverListBody builds a response with one us_denver WireGuard server,
// followed by a signature as real responses are.
func serverListBody(ip, cn string) []byte {
	return []byte(fmt.Sprintf(`{"groups": {"wg": [{"name": "wireguard", "ports": [1337, 1337]}], "meta": [{"ports": [8080]}, {"ports": [443]}]},
		"regions": [{"id": "us_denver", "name": "US Denver", "country": "US", "dns": "denver.example", "port_forward": true,
			"servers": {"wg": [{"ip": %q, "cn": %q}]}}]}

SIGNATUREwithbraces}}==`, ip, cn))
}

type fakeResponse struct {
	body []byte
	err  error
}

// fakeFetch returns the responses in order, then repeats the last one.
func fakeFetch(responses ...fakeResponse) fetchFunc {
	next := 0
	return func(ctx context.Context) ([]byte, http.Header, error) {
		response := responses[min(next, len(responses)-1)]
		next++
		headers := http.Header{"Cache-Control": {"public, max-age=60"}, "Age": {"50"}}
		return response.body, headers, response.err
	}
}

func recordSleeps(sleeps *[]time.Duration) sleepFunc {
	return func(ctx context.Context, wait time.Duration) error {
		*sleeps = append(*sleeps, wait)
		return nil
	}
}

func collectOptions(t *testing.T) CollectOptions {
	t.Helper()
	return CollectOptions{
		Output:      filepath.Join(t.TempDir(), "servers.json"),
		Interval:    5 * time.Second,
		MaxFailures: 3,
	}
}

func readCollected(t *testing.T, path string) collectedServers {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state collectedServers
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestParseServerSnapshot(t *testing.T) {
	snapshot, err := parseServerSnapshot(serverListBody("1.2.3.4", "a"))
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Regions) != 1 || snapshot.Regions[0].Servers["wg"][0] != (Server{Cn: "a", IP: "1.2.3.4"}) {
		t.Errorf("snapshot = %+v", snapshot)
	}

	for name, body := range map[string]string{
		"not json":       `<html>`,
		"no regions":     `{"groups": {}}`,
		"no region id":   `{"regions": [{"name": "x"}]}`,
		"no server cn":   `{"regions": [{"id": "x", "servers": {"wg": [{"ip": "1.2.3.4"}]}}]}`,
		"no server addr": `{"regions": [{"id": "x", "servers": {"wg": [{"cn": "a"}]}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseServerSnapshot([]byte(body)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestTimeUntilRefresh(t *testing.T) {
	tests := []struct {
		name         string
		cacheControl string
		age          string
		want         time.Duration
	}{
		{"remaining plus one", "public, max-age=60", "49", 12 * time.Second},
		{"no age", "max-age=60", "", 61 * time.Second},
		{"bad age", "max-age=60", "soon", 61 * time.Second},
		{"already expired", "max-age=60", "90", time.Second},
		{"no cache header", "", "", defaultCacheTime},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{"Cache-Control": {tt.cacheControl}, "Age": {tt.age}}
			if got := timeUntilRefresh(headers); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestFailureBackoff(t *testing.T) {
	if got := failureBackoff(5*time.Second, 1); got != 10*time.Second {
		t.Errorf("first failure = %s", got)
	}
	if got := failureBackoff(5*time.Second, 2); got != 20*time.Second {
		t.Errorf("second failure = %s", got)
	}
	if got := failureBackoff(5*time.Second, 1000); got != maxFailureBackoff {
		t.Errorf("many failures = %s", got)
	}
}

func TestMergeTracksEndpoints(t *testing.T) {
	state := newCollectedServers()
	first, _ := parseServerSnapshot(serverListBody("1.2.3.4", "b"))
	second, _ := parseServerSnapshot(serverListBody("1.2.3.5", "a"))

	if added := state.merge(first, "t1"); added != 1 {
		t.Errorf("first merge added %d", added)
	}
	if added := state.merge(second, "t2"); added != 1 {
		t.Errorf("second merge added %d", added)
	}
	if added := state.merge(first, "t3"); added != 0 {
		t.Errorf("repeat merge added %d", added)
	}

	if state.Snapshots != 3 || state.TotalEndpoints != 2 || state.FirstCollected != "t1" || state.LastUpdated != "t3" {
		t.Errorf("state = %+v", state)
	}
	servers := state.Regions["us_denver"].Servers["wg"]
	if servers[0].Cn != "a" || servers[1].Cn != "b" {
		t.Errorf("servers are not sorted: %v, %v", servers[0], servers[1])
	}
	if got := *servers[1]; got != (collectedEndpoint{Cn: "b", IP: "1.2.3.4", FirstSeen: "t1", LastSeen: "t3", TimesSeen: 2}) {
		t.Errorf("endpoint = %+v", got)
	}
	if ports := state.ServicePorts["meta"]; len(ports) != 2 || ports[0] != 443 {
		t.Errorf("meta ports = %v", ports)
	}
	if ports := state.ServicePorts["wg"]; len(ports) != 1 {
		t.Errorf("wg ports were not deduplicated: %v", ports)
	}
}

func TestCollectIgnoresRepeatsAndWaitsForCache(t *testing.T) {
	opts := collectOptions(t)
	opts.MaxRounds = 2
	var sleeps []time.Duration

	err := collect(context.Background(), opts, fakeFetch(
		fakeResponse{body: serverListBody("1.2.3.4", "a")},
		fakeResponse{body: serverListBody("1.2.3.4", "a")},
		fakeResponse{body: serverListBody("1.2.3.5", "b")},
	), recordSleeps(&sleeps))
	if err != nil {
		t.Fatal(err)
	}

	state := readCollected(t, opts.Output)
	if state.Snapshots != 2 || state.TotalEndpoints != 2 {
		t.Errorf("snapshots = %d, endpoints = %d", state.Snapshots, state.TotalEndpoints)
	}
	if len(sleeps) != 2 || sleeps[0] != 11*time.Second {
		t.Errorf("sleeps = %v", sleeps)
	}
}

func TestCollectStopsWhenStable(t *testing.T) {
	opts := collectOptions(t)
	opts.StableRounds = 1
	var sleeps []time.Duration

	// The same endpoint with a different signature counts as a new response.
	repeat := append(serverListBody("1.2.3.4", "a"), 'x')
	err := collect(context.Background(), opts, fakeFetch(
		fakeResponse{body: serverListBody("1.2.3.4", "a")},
		fakeResponse{body: repeat},
	), recordSleeps(&sleeps))
	if err != nil {
		t.Fatal(err)
	}
	if state := readCollected(t, opts.Output); state.Snapshots != 2 {
		t.Errorf("snapshots = %d", state.Snapshots)
	}
}

func TestCollectStopsAtDeadline(t *testing.T) {
	opts := collectOptions(t)
	opts.MaxDuration = time.Second
	var sleeps []time.Duration

	err := collect(context.Background(), opts, fakeFetch(fakeResponse{body: serverListBody("1.2.3.4", "a")}), recordSleeps(&sleeps))
	if err != nil {
		t.Fatal(err)
	}
	if len(sleeps) != 0 {
		t.Errorf("should stop rather than sleep past the deadline, sleeps = %v", sleeps)
	}
}

func TestCollectRetriesThenGivesUp(t *testing.T) {
	opts := collectOptions(t)
	var sleeps []time.Duration
	failure := errors.New("connection reset")

	err := collect(context.Background(), opts, fakeFetch(fakeResponse{err: failure}), recordSleeps(&sleeps))
	if !errors.Is(err, failure) {
		t.Fatalf("err = %v", err)
	}
	if len(sleeps) != 2 || sleeps[0] != 10*time.Second || sleeps[1] != 20*time.Second {
		t.Errorf("sleeps = %v", sleeps)
	}
}

func TestCollectFailuresResetAfterSuccess(t *testing.T) {
	opts := collectOptions(t)
	opts.MaxFailures = 2
	opts.MaxRounds = 2
	var sleeps []time.Duration
	failure := fakeResponse{err: errors.New("connection reset")}

	err := collect(context.Background(), opts, fakeFetch(
		failure,
		fakeResponse{body: serverListBody("1.2.3.4", "a")},
		failure,
		fakeResponse{body: serverListBody("1.2.3.5", "b")},
	), recordSleeps(&sleeps))
	if err != nil {
		t.Fatal(err)
	}
}

func TestCollectStopsOnCancel(t *testing.T) {
	opts := collectOptions(t)
	ctx, cancel := context.WithCancel(context.Background())
	sleep := func(ctx context.Context, wait time.Duration) error {
		cancel()
		return sleepContext(ctx, wait)
	}

	err := collect(ctx, opts, fakeFetch(fakeResponse{body: serverListBody("1.2.3.4", "a")}), sleep)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if state := readCollected(t, opts.Output); state.TotalEndpoints != 1 {
		t.Errorf("results should be saved before cancelling, endpoints = %d", state.TotalEndpoints)
	}
}

func TestCollectMergesUnlessFresh(t *testing.T) {
	opts := collectOptions(t)
	opts.MaxRounds = 1
	run := func(body []byte) {
		t.Helper()
		var sleeps []time.Duration
		if err := collect(context.Background(), opts, fakeFetch(fakeResponse{body: body}), recordSleeps(&sleeps)); err != nil {
			t.Fatal(err)
		}
	}

	run(serverListBody("1.2.3.4", "a"))
	run(serverListBody("1.2.3.5", "b"))
	if state := readCollected(t, opts.Output); state.TotalEndpoints != 2 || state.Snapshots != 2 {
		t.Errorf("merge: endpoints = %d, snapshots = %d", state.TotalEndpoints, state.Snapshots)
	}

	opts.Fresh = true
	run(serverListBody("1.2.3.6", "c"))
	if state := readCollected(t, opts.Output); state.TotalEndpoints != 1 || state.Snapshots != 1 {
		t.Errorf("fresh: endpoints = %d, snapshots = %d", state.TotalEndpoints, state.Snapshots)
	}
}

func TestCollectRefusesOtherFiles(t *testing.T) {
	for name, content := range map[string]string{
		"not json":   "precious notes",
		"other json": `{"some": "other file"}`,
	} {
		t.Run(name, func(t *testing.T) {
			opts := collectOptions(t)
			opts.MaxRounds = 1
			if err := os.WriteFile(opts.Output, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}

			var sleeps []time.Duration
			err := collect(context.Background(), opts, fakeFetch(fakeResponse{body: serverListBody("1.2.3.4", "a")}), recordSleeps(&sleeps))
			if err == nil {
				t.Fatal("expected an error")
			}
			data, err := os.ReadFile(opts.Output)
			if err != nil || string(data) != content {
				t.Errorf("file was changed: %q, %v", data, err)
			}
		})
	}
}

func TestCollectOutputLoadsAsServerFile(t *testing.T) {
	opts := collectOptions(t)
	opts.MaxRounds = 1
	var sleeps []time.Duration

	if err := collect(context.Background(), opts, fakeFetch(fakeResponse{body: serverListBody("1.2.3.4", "a")}), recordSleeps(&sleeps)); err != nil {
		t.Fatal(err)
	}

	servers, err := LoadServerFile(opts.Output)
	if err != nil {
		t.Fatal(err)
	}
	if got := servers["us_denver"]; len(got) != 1 || got[0] != (Server{Cn: "a", IP: "1.2.3.4"}) {
		t.Errorf("servers = %v", servers)
	}
}
