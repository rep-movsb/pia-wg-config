package pia

import (
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testToken = "secret-test-token"

func writeServerFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "servers.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadServerFile(t *testing.T) {
	path := writeServerFile(t, `{"snapshots": 2, "regions": {
		"us_denver": {"name": "US Denver", "servers": {
			"wg": [
				{"ip": "1.2.3.4", "cn": "denver1", "times_seen": 2},
				{"ip": "1.2.3.5", "cn": "denver2"}
			],
			"meta": [{"ip": "9.9.9.9", "cn": "denver1"}]
		}},
		"uk_london": {"servers": {"wg": [{"ip": "5.6.7.8", "cn": "london1"}]}},
		"no_wireguard": {"servers": {"meta": [{"ip": "9.9.9.8", "cn": "x"}]}}
	}}`)

	got, err := LoadServerFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d regions, want 2: %v", len(got), got)
	}
	if len(got["us_denver"]) != 2 || got["us_denver"][0] != (Server{Cn: "denver1", IP: "1.2.3.4"}) {
		t.Errorf("us_denver = %v", got["us_denver"])
	}
}

func TestLoadServerFileRejectsBadInput(t *testing.T) {
	tests := map[string]string{
		"not json":       `nope`,
		"no servers":     `{"regions": {}}`,
		"path traversal": `{"regions": {"../evil": {"servers": {"wg": [{"ip": "1.2.3.4", "cn": "a"}]}}}}`,
		"parent region":  `{"regions": {"..": {"servers": {"wg": [{"ip": "1.2.3.4", "cn": "a"}]}}}}`,
		"bad ip":         `{"regions": {"us": {"servers": {"wg": [{"ip": "../../evil", "cn": "a"}]}}}}`,
		"missing cn":     `{"regions": {"us": {"servers": {"wg": [{"ip": "1.2.3.4"}]}}}}`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadServerFile(writeServerFile(t, content)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// startAddKeyServer serves addKey on loopback port 1337, the port PIA uses.
func startAddKeyServer(t *testing.T, result AddKeyResult) *PIAClient {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:1337")
	if err != nil {
		t.Skipf("port 1337 unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/addKey" || r.URL.Query().Get("pt") != testToken || r.URL.Query().Get("pubkey") != "pub+key" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	t.Cleanup(server.Close)

	client := NewPIAServerClient("user", "pass", false)
	client.caCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	return client
}

func TestForServerAddsKeyToThatServer(t *testing.T) {
	want := AddKeyResult{Status: "OK", ServerIP: "1.2.3.4", DNSServers: []string{"10.0.0.1"}}
	client := startAddKeyServer(t, want)

	got, err := client.ForServer(Server{Cn: "127.0.0.1", IP: "127.0.0.1"}).AddKey(testToken, "pub+key")
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerIP != want.ServerIP {
		t.Errorf("ServerIP = %q, want %q", got.ServerIP, want.ServerIP)
	}
}

func TestForServerIsSafeForConcurrentUse(t *testing.T) {
	client := startAddKeyServer(t, AddKeyResult{Status: "OK"})

	var requests sync.WaitGroup
	for range 16 {
		requests.Go(func() {
			if _, err := client.ForServer(Server{Cn: "127.0.0.1", IP: "127.0.0.1"}).AddKey(testToken, "pub+key"); err != nil {
				t.Error(err)
			}
		})
	}
	requests.Wait()
}

func TestAddKeyRejectsErrorStatus(t *testing.T) {
	client := startAddKeyServer(t, AddKeyResult{Status: "ERROR"})

	_, err := client.ForServer(Server{Cn: "127.0.0.1", IP: "127.0.0.1"}).AddKey(testToken, "pub+key")
	if err == nil || !strings.Contains(err.Error(), "ERROR") {
		t.Errorf("err = %v, want rejected status", err)
	}
}

func TestAddKeyErrorDoesNotContainToken(t *testing.T) {
	client := NewPIAServerClient("user", "pass", false)
	client.caCert = []byte("unused")

	// Nothing listens on this loopback address, so the request itself fails.
	_, err := client.ForServer(Server{Cn: "127.0.0.2", IP: "127.0.0.2"}).AddKey(testToken, "pub+key")
	if err == nil {
		t.Skip("something is listening on 127.0.0.2:1337")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error leaks the token: %v", err)
	}
}

func TestGetTokenReusesToken(t *testing.T) {
	client := NewPIAServerClient("user", "pass", false)
	client.token = testToken

	// A cached token must be returned without contacting PIA.
	got, err := client.ForServer(Server{}).GetToken()
	if err != nil || got != testToken {
		t.Errorf("GetToken() = %q, %v", got, err)
	}
}

func TestGenerateFailsWithoutDNSServers(t *testing.T) {
	generator := NewPIAWgGenerator(&PIAClientMock{}, PIAWgGeneratorConfig{})
	if _, err := generator.generateConfig(AddKeyResult{}, "key"); err == nil {
		t.Error("expected an error")
	}
}
