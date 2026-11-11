package pia

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// serverFile is the part of the collect command's output needed to reach each
// WireGuard server.
type serverFile struct {
	Regions map[string]struct {
		Servers struct {
			Wg []Server `json:"wg"`
		} `json:"servers"`
	} `json:"regions"`
}

// LoadServerFile reads the WireGuard servers from a collected server list.
// Region IDs and IPs are validated because callers use them to name files.
func LoadServerFile(path string) (ServerList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "error reading server file")
	}

	var file serverFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, errors.Wrap(err, "error parsing server file")
	}

	servers := ServerList{}
	for region, entry := range file.Regions {
		if region == "" || region == "." || region == ".." || region != filepath.Base(region) {
			return nil, fmt.Errorf("invalid region ID %q in server file", region)
		}
		for _, server := range entry.Servers.Wg {
			if net.ParseIP(server.IP) == nil || server.Cn == "" {
				return nil, fmt.Errorf("invalid server (ip %q, cn %q) in region %q", server.IP, server.Cn, region)
			}
			servers[Region(region)] = append(servers[Region(region)], server)
		}
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("no WireGuard servers found in %s", path)
	}

	return servers, nil
}
