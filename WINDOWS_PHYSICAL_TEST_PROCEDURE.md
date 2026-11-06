# Windows physical-network binding — functional test procedure

Status: the implementation in `common/dialer/physical_windows.go` and
`protocol/hydra/adaptive_physical_windows.go` is **compile-verified only**
(GOOS=windows GOARCH=amd64 `go build ./...` exit 0, `go vet` clean, offline
Go 1.25.6). Compile proof is NOT functional proof. This document is the
functional gate for whoever first runs it on a real Windows host.

## 1. Build the artifacts

From this Linux machine (offline, pinned toolchain):

```bash
export PATH=/home/varingait/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.6.linux-amd64/bin:$PATH
cd /home/varingait/src/hiddify-core/hiddify-sing-box
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly \
  GOOS=windows GOARCH=amd64 go build -o sing-box.exe ./cmd/sing-box
```

Or on the Windows host with Go >= 1.25: `go build -o sing-box.exe ./cmd/sing-box`.

Server side: a reachable real Rust hydra server (vpns/hydra deployment, e.g.
hetzner) with its address, CA cert and network key.

## 2. Untagged test suites on Windows (protocol health, not binding)

These suites carry no build tag and therefore run on Windows:

- `recovery_persistence_integration_test.go` (Recovery)
- `rtc_fault_integration_test.go`, `rtc_outbound_integration_test.go` (RTC)
- `adaptive_catalogue_test.go`, `adaptive_catalogue_integration_test.go`,
  `catalogue_test.go` (Catalogue)

```powershell
$env:HYDRA_BENCH_SERVER="<ip:port of real Rust server>"
$env:HYDRA_BENCH_CA="<path to CA pem>"
$env:HYDRA_BENCH_PUBKEY="<server pubkey>"
go test ./protocol/hydra -run "TestRecovery|TestRTC|TestCatalogue" -count=1 -v
```

Note: the interface seams (`HYDRA_CHAIN_INTERFACE`, `HYDRA_BENCH_INTERFACE`)
are consumed only by linux-tagged test files
(`control_chain_linux_test.go`, `external_bench_linux_test.go`), so these
suites prove protocol health on Windows but do NOT exercise interface
binding. Binding is proven by the manual scenario below.

## 3. Manual two-interface scenario (the actual binding proof)

### 3.1 Host setup

- One physical LAN adapter (example name `Ethernet`) with internet egress.
- One active VPN adapter (WireGuard/any client that installs a route toward
  the server). Enumerate: `Get-NetAdapter | Where-Object Status -eq Up`.
- Baseline check: `route print -4` must show the VPN route toward the server
  (that is what the binding has to bypass).
- Identify the VPN adapter name, e.g. `VPN` below; substitute real names.

### 3.2 Config

Hydra outbound with adaptive physical options (JSON nesting per
`option/hydra.go`: outbound `"adaptive"` object):

```json
{
  "outbounds": [
    {
      "type": "hydra",
      "tag": "hydra-out",
      "adaptive": {
        "physical_interface": "Ethernet",
        "physical_dns_servers": ["<literal-ip>:53", "<literal-ip2>:53"],
        "candidates": [ { "...": "candidate pointing at the real Rust server" } ],
        "proof_url": "<server proof url>",
        "network_key": "<key>"
      }
    }
  ],
  "inbounds": [ { "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 12334 } ]
}
```

Run: `.\sing-box.exe run -c phys.json` (expect no startup error; a bad
interface name must fail startup — see negative controls).

### 3.3 Positive proof A — adapter statistics (PowerShell)

```powershell
$phys = "Ethernet"; $vpn = "VPN"
$snap = { Get-NetAdapterStatistics -Name $phys, $vpn |
          Select-Object Name, SentBytes, ReceivedBytes | ConvertTo-Json }
$snap.Invoke() | Out-File before.json
# drive ~50-100 MB through the tunnel via the local proxy, e.g.:
curl.exe --proxy http://127.0.0.1:12334 http://speedtest.example/file.bin -o NUL
$snap.Invoke() | Out-File after.json
```

Expected: `Ethernet` SentBytes/ReceivedBytes grow by approximately the
transferred volume; `VPN` deltas stay at background noise level for that
window. `before.json` + `after.json` are the artifacts.

### 3.4 Positive proof B — pktmon capture (admin shell)

```powershell
pktmon filter remove
pktmon filter add HYDRA -p <server-port>
pktmon start -c --pkt-size 128 -f C:\temp\phys.etl
# drive traffic as above
pktmon stop
pktmon etl2txt C:\temp\phys.etl > C:\temp\phys.txt
```

Expected: handshake + data packets for the server flow appear on the
`Ethernet` component (`pktmon comp list` shows per-NIC components) and no
packets for that flow appear on the VPN adapter component. `phys.txt`
annotated with the component names is the artifact.

### 3.5 Positive proof C — server-side source IP (strongest single artifact)

While the VPN adapter is UP and would normally carry all traffic, the Rust
server's session log must show the client source IP equal to the ISP public
IP (`Ethernet` egress), NOT the VPN exit IP. Compare against a control run
with the binding removed (plain config): that one shows the VPN exit IP.
This single artifact proves bypass of the active VPN adapter independently
of any local counter.

### 3.6 Negative controls (fail-closed — each must be REFUSED)

| Change to config                                            | Expected result                                        |
|-------------------------------------------------------------|--------------------------------------------------------|
| remove `physical_interface` (empty)                          | adaptive physical dialer refuses: explicit interface required |
| `physical_interface: "NoSuchAdapter"`                        | refuses: invalid physical interface                    |
| `physical_dns_servers: ["example.com:53"]` (hostname)        | refuses: must be literal IP:port                       |
| `physical_dns_servers: []` + domain-based candidate          | refuses at dial: domain requires explicit physical DNS  |
| `physical_interface` pointing at the VPN adapter             | starts, but traffic leaves the VPN adapter (statistics prove binding correctness, not bypass) |
| unplug/disable `Ethernet` after startup                      | dial attempts fail with "interface changed"/no usable unicast source — never silent fallback |

### 3.7 UDP path

The hydra transport itself is QUIC-based, so the `ListenPacket`/`WriteTo`
path (per-write peer validation, `IP_UNICAST_IF`/`IPV6_UNICAST_IF` on a
bound UDP socket) is exercised by every tunnel run above. To make it
explicit in pktmon, add the candidate's UDP port to the filter and confirm
the QUIC packets sit on the `Ethernet` component.

## 4. Acceptance criteria

1. All three untagged suites pass on Windows.
2. Proof A: physical adapter carries the flow; VPN adapter does not.
3. Proof B: capture shows the flow on the physical component only.
4. Proof C: server sees the ISP public IP while VPN is up.
5. Every negative control refuses with the typed error
   (`physical path unavailable` wrap family) instead of falling back.
