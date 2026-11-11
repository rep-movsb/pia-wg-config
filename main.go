package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/kylegrantlucas/pia-wg-config/pia"
	cli "github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:   "pia-wg-config",
		Usage:  "generate a wireguard config for private internet access",
		Action: defaultAction,

		Commands: []*cli.Command{
			{
				Name:    "regions",
				Aliases: []string{"r"},
				Usage:   "List all available PIA regions",
				Action:  listRegions,
			},
			{
				Name:    "collect",
				Aliases: []string{"c"},
				Usage:   "Poll PIA's server list and save every endpoint seen to JSON, for use with --servers-file",
				Action:  collectServers,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Value:   "pia_servers.json",
						Usage:   "The JSON file to write",
					},
					&cli.IntFlag{
						Name:  "stable-rounds",
						Value: 60,
						Usage: "Stop after this many new responses add no endpoints, 0 to disable",
					},
					&cli.IntFlag{
						Name:  "max-rounds",
						Usage: "Stop after this many new responses, 0 for no limit",
					},
					&cli.IntFlag{
						Name:  "max-seconds",
						Usage: "Stop after this many seconds, 0 for no limit",
					},
					&cli.Float64Flag{
						Name:  "interval",
						Value: 5,
						Usage: "Minimum seconds between requests",
					},
					&cli.Float64Flag{
						Name:  "timeout",
						Value: 30,
						Usage: "Request timeout in seconds",
					},
					&cli.IntFlag{
						Name:  "max-failures",
						Value: 10,
						Usage: "Stop after this many consecutive failures",
					},
					&cli.BoolFlag{
						Name:  "fresh",
						Usage: "Overwrite the output file instead of merging into it",
					},
				},
			},
		},

		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "outfile",
				Aliases: []string{"o"},
				Usage:   "The file to write the wireguard config to",
			},
			&cli.StringFlag{
				Name:    "servers-file",
				Aliases: []string{"s"},
				Usage:   "JSON server list from the collect command; writes one config per WireGuard server to --outdir (use -r to limit to one region)",
			},
			&cli.StringFlag{
				Name:    "outdir",
				Aliases: []string{"d"},
				Value:   "pia-configs",
				Usage:   "The directory to write configs to when using --servers-file",
			},
			&cli.IntFlag{
				Name:    "concurrency",
				Aliases: []string{"j"},
				Value:   8,
				Usage:   "The number of servers to contact at once when using --servers-file",
			},
			&cli.StringFlag{
				Name:    "region",
				Aliases: []string{"r"},
				Value:   "us_california",
				Usage:   "The private internet access region to connect to (use 'regions' command to list all available regions)",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Value:   false,
				Usage:   "Print verbose output",
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func defaultAction(c *cli.Context) error {
	// Validate arguments
	if c.NArg() < 2 {
		fmt.Println("Error: Username and password are required")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  pia-wg-config [OPTIONS] USERNAME PASSWORD")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  pia-wg-config myuser mypass")
		fmt.Println("  pia-wg-config -r uk_london myuser mypass")
		fmt.Println("  pia-wg-config -o config.conf -r de_frankfurt myuser mypass")
		fmt.Println("  pia-wg-config -s pia_servers.json -d configs myuser mypass")
		fmt.Println()
		fmt.Println("To see available regions:")
		fmt.Println("  pia-wg-config regions")
		return cli.Exit("", 1)
	}

	// get username and password
	username := c.Args().Get(0)
	password := c.Args().Get(1)
	verbose := c.Bool("verbose")
	region := c.String("region")

	if username == "" || password == "" {
		return cli.Exit("Error: Username and password cannot be empty", 1)
	}

	if c.String("servers-file") != "" {
		return generateFromServerFile(c, username, password)
	}

	// create pia client
	if verbose {
		log.Printf("Creating PIA client for region: %s", region)
	}
	piaClient, err := pia.NewPIAClient(username, password, region, verbose)
	if err != nil {
		if verbose {
			log.Printf("Failed to create PIA client: %v", err)
		}
		fmt.Printf("Error: Failed to connect to PIA servers\n")
		fmt.Printf("This could be due to:\n")
		fmt.Printf("  - Invalid username or password\n")
		fmt.Printf("  - Invalid region '%s' (run 'pia-wg-config regions' to see available regions)\n", region)
		fmt.Printf("  - Network connectivity issues\n")
		fmt.Printf("  - PIA service unavailable\n")
		fmt.Printf("\nTry running with -v flag for more details\n")
		return cli.Exit("", 1)
	}

	// create wg config generator
	if verbose {
		log.Print("creating wg config generator")
	}
	wgConfigGenerator := pia.NewPIAWgGenerator(piaClient, pia.PIAWgGeneratorConfig{Verbose: verbose})

	// generate wg config
	if verbose {
		log.Print("Generating wireguard config")
	}
	config, err := wgConfigGenerator.Generate()
	if err != nil {
		if verbose {
			log.Printf("Failed to generate config: %v", err)
		}
		fmt.Printf("Error: Failed to generate Wireguard configuration\n")
		fmt.Printf("This could be due to:\n")
		fmt.Printf("  - Authentication failure (check your PIA credentials)\n")
		fmt.Printf("  - Server communication issues\n")
		fmt.Printf("  - Region server unavailable\n")
		fmt.Printf("\nTry running with -v flag for more details\n")
		return cli.Exit("", 1)
	}

	outfile := c.String("outfile")
	if outfile != "" {
		// write config to file
		err = os.WriteFile(outfile, []byte(config), 0600) // More secure permissions
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error: Failed to write config to file '%s': %v", outfile, err), 1)
		}
		if verbose {
			log.Printf("Wireguard config written to: %s", outfile)
		}
		fmt.Printf("✓ Wireguard config generated successfully: %s\n", outfile)
		fmt.Printf("You can now connect using: sudo wg-quick up %s\n", outfile)
	} else {
		// print config to stdout
		fmt.Println(config)
	}

	return nil
}

// generateFromServerFile writes one config per WireGuard server in a JSON file.
func generateFromServerFile(c *cli.Context, username, password string) error {
	if c.IsSet("outfile") {
		return cli.Exit("Error: --outfile cannot be used with --servers-file, use --outdir", 1)
	}

	concurrency := c.Int("concurrency")
	if concurrency < 1 {
		return cli.Exit("Error: --concurrency must be at least 1", 1)
	}

	servers, err := pia.LoadServerFile(c.String("servers-file"))
	if err != nil {
		return cli.Exit(fmt.Sprintf("Error: %v", err), 1)
	}

	if c.IsSet("region") {
		region := pia.Region(c.String("region"))
		if _, exists := servers[region]; !exists {
			return cli.Exit(fmt.Sprintf("Error: region '%s' has no WireGuard servers in the server file", region), 1)
		}
		servers = pia.ServerList{region: servers[region]}
	}

	verbose := c.Bool("verbose")
	client := pia.NewPIAServerClient(username, password, verbose)
	written, failed, err := writeServerConfigs(client, servers, c.String("outdir"), concurrency, verbose)
	if err != nil {
		return cli.Exit(fmt.Sprintf("Error: %v", err), 1)
	}

	fmt.Printf("✓ Wrote %d configs to %s, %d failed\n", written, c.String("outdir"), failed)
	if failed > 0 {
		return cli.Exit("", 1)
	}
	return nil
}

// serverConfigClient is the part of pia.PIAClient used for batch generation.
type serverConfigClient interface {
	GetToken() (string, error)
	ForServer(server pia.Server) pia.PIAWgClient
}

// serverJob is one config to generate.
type serverJob struct {
	region string
	server pia.Server
}

// writeServerConfigs generates <outdir>/<region>/<ip>.conf for every server,
// contacting up to concurrency servers at once. Files are named by IP because
// wg-quick uses the file name as the interface name, which is limited to 15
// characters. A server that fails is reported and skipped, since collected
// lists can contain servers that no longer exist. A local write failure stops
// the run, because every later server would fail the same way.
func writeServerConfigs(client serverConfigClient, servers pia.ServerList, outdir string, concurrency int, verbose bool) (written, failed int, err error) {
	// Log in once up front so bad credentials stop the run immediately.
	if _, err := client.GetToken(); err != nil {
		return 0, 0, fmt.Errorf("failed to authenticate with PIA: %v", err)
	}

	regions := make([]string, 0, len(servers))
	for region := range servers {
		regions = append(regions, string(region))
	}
	sort.Strings(regions)

	var jobs []serverJob
	for _, region := range regions {
		// Configs contain private keys, so keep the directories private.
		if err := os.MkdirAll(filepath.Join(outdir, region), 0700); err != nil {
			return 0, 0, fmt.Errorf("failed to create output directory: %v", err)
		}
		for _, server := range servers[pia.Region(region)] {
			jobs = append(jobs, serverJob{region: region, server: server})
		}
	}

	// mu guards everything below, and also serializes file writes and output
	// so that lines stay whole and duplicate IPs cannot interleave in a file.
	var (
		mu       sync.Mutex
		nextJob  int
		done     int
		writeErr error
	)

	next := func() (serverJob, bool) {
		mu.Lock()
		defer mu.Unlock()
		if writeErr != nil || nextJob >= len(jobs) {
			return serverJob{}, false
		}
		job := jobs[nextJob]
		nextJob++
		return job, true
	}

	record := func(job serverJob, config string, genErr error) {
		mu.Lock()
		defer mu.Unlock()
		done++
		if genErr != nil {
			failed++
			fmt.Fprintf(os.Stderr, "[%d/%d] %s %s (%s) failed: %v\n", done, len(jobs), job.region, job.server.IP, job.server.Cn, genErr)
			return
		}

		path := filepath.Join(outdir, job.region, job.server.IP+".conf")
		if err := os.WriteFile(path, []byte(config+"\n"), 0600); err != nil {
			if writeErr == nil {
				writeErr = fmt.Errorf("failed to write config: %v", err)
			}
			return
		}
		written++
		fmt.Printf("[%d/%d] %s\n", done, len(jobs), path)
	}

	var workers sync.WaitGroup
	for range min(concurrency, len(jobs)) {
		workers.Go(func() {
			for {
				job, ok := next()
				if !ok {
					return
				}
				generator := pia.NewPIAWgGenerator(client.ForServer(job.server), pia.PIAWgGeneratorConfig{Verbose: verbose})
				config, err := generator.Generate()
				record(job, config, err)
			}
		})
	}
	workers.Wait()

	return written, failed, writeErr
}

func collectServers(c *cli.Context) error {
	ctx, stop := signal.NotifyContext(c.Context, os.Interrupt, syscall.SIGTERM)
	defer stop()

	output := c.String("output")
	err := pia.CollectServers(ctx, pia.CollectOptions{
		Output:       output,
		Fresh:        c.Bool("fresh"),
		StableRounds: c.Int("stable-rounds"),
		MaxRounds:    c.Int("max-rounds"),
		MaxDuration:  time.Duration(c.Int("max-seconds")) * time.Second,
		Interval:     time.Duration(c.Float64("interval") * float64(time.Second)),
		Timeout:      time.Duration(c.Float64("timeout") * float64(time.Second)),
		MaxFailures:  c.Int("max-failures"),
	})
	if errors.Is(err, context.Canceled) {
		log.Printf("interrupted, results so far are in %s", output)
		return cli.Exit("", 130)
	}
	if err != nil {
		return cli.Exit(fmt.Sprintf("Error: %v", err), 1)
	}
	return nil
}

func listRegions(c *cli.Context) error {
	fmt.Println("Fetching available regions from PIA...")

	// Create a dummy client just to get the server list
	piaClient, err := pia.NewPIAClient("", "", "us_california", false)
	if err != nil {
		return fmt.Errorf("failed to fetch regions: %v", err)
	}

	regions, err := piaClient.GetAvailableRegions()
	if err != nil {
		return fmt.Errorf("failed to get regions: %v", err)
	}

	// Sort regions for consistent output
	var regionList []string
	for region := range regions {
		regionList = append(regionList, string(region))
	}
	sort.Strings(regionList)

	fmt.Println("\nAvailable PIA regions:")
	fmt.Println("======================")
	for _, region := range regionList {
		fmt.Printf("  %s\n", region)
	}
	fmt.Printf("\nTotal: %d regions available\n", len(regionList))
	fmt.Println("\nUsage example:")
	fmt.Println("  pia-wg-config -r uk_london USERNAME PASSWORD")

	return nil
}
