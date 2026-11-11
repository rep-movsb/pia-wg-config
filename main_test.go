package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kylegrantlucas/pia-wg-config/pia"
)

type fakeServerClient struct {
	tokenErr error
	logins   int
}

func (f *fakeServerClient) GetToken() (string, error) {
	f.logins++
	return "token", f.tokenErr
}

func (f *fakeServerClient) ForServer(server pia.Server) pia.PIAWgClient {
	return &fakeBoundClient{server: server}
}

type fakeBoundClient struct {
	server pia.Server
}

func (f *fakeBoundClient) GetToken() (string, error) { return "token", nil }

func (f *fakeBoundClient) AddKey(token, publickey string) (pia.AddKeyResult, error) {
	if f.server.Cn == "dead" {
		return pia.AddKeyResult{}, errors.New("no route to host")
	}
	return pia.AddKeyResult{
		ServerIP:   f.server.IP,
		ServerKey:  "server-key",
		PeerIP:     "10.0.0.2",
		DNSServers: []string{"10.0.0.1"},
	}, nil
}

func TestWriteServerConfigs(t *testing.T) {
	outdir := filepath.Join(t.TempDir(), "configs")
	servers := pia.ServerList{
		"us_denver": {{Cn: "denver1", IP: "1.2.3.4"}, {Cn: "dead", IP: "1.2.3.5"}},
		"uk_london": {{Cn: "london1", IP: "255.255.255.255"}},
	}

	written, failed, err := writeServerConfigs(&fakeServerClient{}, servers, outdir, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if written != 2 || failed != 1 {
		t.Errorf("written = %d, failed = %d, want 2 and 1", written, failed)
	}

	path := filepath.Join(outdir, "us_denver", "1.2.3.4.conf")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "Endpoint = 1.2.3.4:1337") {
		t.Errorf("config has wrong endpoint:\n%s", content)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("config mode = %o, want 600", info.Mode().Perm())
	}

	if _, err := os.Stat(filepath.Join(outdir, "us_denver", "1.2.3.5.conf")); !os.IsNotExist(err) {
		t.Errorf("failed server should have no config, stat err = %v", err)
	}
}

func TestWriteServerConfigsStopsOnBadLogin(t *testing.T) {
	outdir := filepath.Join(t.TempDir(), "configs")
	client := &fakeServerClient{tokenErr: errors.New("401")}
	servers := pia.ServerList{"us_denver": {{Cn: "denver1", IP: "1.2.3.4"}}}

	if _, _, err := writeServerConfigs(client, servers, outdir, 1, false); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := os.Stat(outdir); !os.IsNotExist(err) {
		t.Errorf("no output should be created on bad login, stat err = %v", err)
	}
}

func TestWriteServerConfigsStopsOnWriteFailure(t *testing.T) {
	outdir := filepath.Join(t.TempDir(), "configs")
	// A directory where the first config belongs makes that write fail.
	if err := os.MkdirAll(filepath.Join(outdir, "us_denver", "1.2.3.4.conf"), 0700); err != nil {
		t.Fatal(err)
	}
	servers := pia.ServerList{"us_denver": {{Cn: "a", IP: "1.2.3.4"}, {Cn: "b", IP: "1.2.3.5"}}}

	written, _, err := writeServerConfigs(&fakeServerClient{}, servers, outdir, 1, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if written != 0 {
		t.Errorf("written = %d, want the run to stop before the second server", written)
	}
}

// barrierClient fails unless the expected number of AddKey calls overlap.
type barrierClient struct {
	fakeServerClient
	expected int32
	arrived  atomic.Int32
	release  chan struct{}
}

func (b *barrierClient) ForServer(server pia.Server) pia.PIAWgClient {
	return &barrierBoundClient{fakeBoundClient: fakeBoundClient{server: server}, barrier: b}
}

type barrierBoundClient struct {
	fakeBoundClient
	barrier *barrierClient
}

func (b *barrierBoundClient) AddKey(token, publickey string) (pia.AddKeyResult, error) {
	if b.barrier.arrived.Add(1) == b.barrier.expected {
		close(b.barrier.release)
	}
	select {
	case <-b.barrier.release:
		return b.fakeBoundClient.AddKey(token, publickey)
	case <-time.After(5 * time.Second):
		return pia.AddKeyResult{}, errors.New("requests did not overlap")
	}
}

func TestWriteServerConfigsRunsConcurrently(t *testing.T) {
	outdir := filepath.Join(t.TempDir(), "configs")
	servers := pia.ServerList{
		"us_denver": {{Cn: "a", IP: "1.2.3.4"}, {Cn: "b", IP: "1.2.3.5"}},
		"uk_london": {{Cn: "c", IP: "1.2.3.6"}, {Cn: "d", IP: "1.2.3.7"}},
	}
	client := &barrierClient{expected: 4, release: make(chan struct{})}

	written, failed, err := writeServerConfigs(client, servers, outdir, 4, false)
	if err != nil {
		t.Fatal(err)
	}
	if written != 4 || failed != 0 {
		t.Errorf("written = %d, failed = %d, want 4 and 0", written, failed)
	}
}
