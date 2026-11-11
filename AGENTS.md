# pia-wg-config

Go CLI that generates WireGuard configs for Private Internet Access (PIA). Public repo (github.com/kylegrantlucas/pia-wg-config).

## Layout
- `main.go` — urfave/cli entrypoint (`regions` and `collect` subcommands, `-r/--region`, `-o/--outfile`, `-v/--verbose`), plus batch mode (`-s/--servers-file`, `-d/--outdir`, `-j/--concurrency`) that writes `<outdir>/<region>/<ip>.conf` with a worker pool. `main_test.go` covers batch mode with fakes.
- `pia/pia.go` — PIA API client: server list (`serverlist.piaservers.net/vpninfo/servers/v4`), token (central `www.privateinternetaccess.com/api/client/v2/token`, cached per client), `addKey` against the region's WG server or a specific one via `ForServer` (PIA CA, custom dialer). `PIAClient` is shared by batch workers; its mutex guards the token and CA.
- `pia/collect.go` — `collect` command: polls the server list (one random server per region/service per response, CDN-cached 60s) and merges every endpoint into JSON. `pia/serverfile.go` loads that JSON for batch mode.
- `pia/wg.go` — key generation + config rendering. Tests in `pia/*_test.go`; network calls are faked, and `addKey` tests use a TLS server on loopback port 1337 (skipped if busy).

## Commands (run inside `nix develop` / direnv)
- Test: `go test ./...` · Vet: `go vet ./...` · Build: `go build` (or `make build` to stamp version)
- Lint: `golangci-lint run` (currently reports 6 pre-existing findings; not gated in CI)
- Smoke (network, no creds): `go run . regions` · `go run . collect -o /tmp/s.json --max-rounds 1`

## Invariants / gotchas
- Go 1.27 (go directive `1.27.0`, toolchain `go1.27.2`); flake pins nixpkgs `go_1_27` with `GOTOOLCHAIN=local`. Keep `.github/workflows/ci.yml` on the same version.
- No `vendor/` — modules are fetched normally.
- Never log credentials, tokens or private keys; generated `*.conf` files contain private keys and are gitignored. The token is in the `addKey` URL, so strip `*url.Error` before returning request errors.
- wg-quick uses the config file name as the interface name (max 15 chars), which is why batch files are named by IP.
- Branch `wip/stdlib-cli` holds an unfinished stdlib-only CLI rewrite (drops urfave/cli, pkg/errors, dns).
