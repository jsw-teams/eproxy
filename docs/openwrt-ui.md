# eproxy OpenWrt LuCI management: actual end-to-end contract

## Architecture (v0.2)

One source of truth: `/etc/config/eproxy` (UCI) → the Go daemon's `-uci` parser → authenticated proxy listeners and ordered outbound rules. LuCI only uses the standard rpcd `uci` ACL and read-only `service.list`; it does not run arbitrary shell commands or store a separate configuration database. The procd init script checks the exact same UCI file before start and reloads on UCI changes.

**Basic UI is implemented:** Service status (via procd), enable/disable, loopback listener, local authentication, dial timeout and default route; outbound node add/edit/delete with protocol-sensitive fields (direct, HTTP upstream, SOCKS5 upstream, Trojan TLS, VLESS TCP TLS, Shadowsocks AEAD); ordered domain rule add/edit/delete with block and named outbounds. Hidden fields are not silently treated as unsupported protocols. Values are server-validated, and malformed UCI configurations cannot start the process.

The UI runs as a normal LuCI view at `Services → eproxy`, inherits the current LuCI URL prefix, and does **not** change the router root `/`. The router-specific `/router/` reverse-proxy mounting remains a separate, unverified firmware task.

## OpenWrt installation and usage

1. Use the standard `src-git eproxy https://github.com/jsw-teams/eproxy.git` feed; pin to an approved commit.
2. Install the two APK packages `eproxy-core` and `luci-app-eproxy` from the **matching target/ABI** build; do not install an unverified CPE-S10 experiment image.
3. Open LuCI → Services → eproxy. Configure an outbound, its credentials, a matching domain rule, and the default outbound.
4. Save & Apply. The service is disabled initially. Enable it only after nodes and credentials have been configured. The service refuses invalid or unsupported protocol settings.
5. Test the loopback proxy from the router itself, for example `curl --proxy http://127.0.0.1:1080 https://example.com`, and use the standard system log to inspect errors.
6. LuCI's service indicator reports only process running/stopped, **not** remote reachability. It is not a full latency or throughput dashboard.

`/etc/config/eproxy` is installed as mode 0600. The init script re-applies mode 0600 after LuCI/UCI changes before starting; never put private subscriptions or server passwords into public Git.

## Protocol matrix — *exactly what the core understands*

| Local ingress / outbound | Supported | Important restrictions |
| --- | --- | --- |
| HTTP proxy + CONNECT local TCP | Yes | Loopback-only, HTTP Basic optional |
| SOCKS5 CONNECT + direct UDP ASSOCIATE | Yes | Loopback, optional password, direct UDP only |
| direct / HTTP CONNECT / SOCKS5 upstream | Yes | Password-bearing upstreams restricted to loopback |
| Trojan TLS TCP | Yes | Verified server cert, TCP only, independently hosted interoperability still pending |
| VLESS TCP over TLS | Yes | Standard UUID/TLS only; no REALITY, WS, gRPC or XTLS |
| Shadowsocks AEAD AES-256-GCM | Yes | Legacy AEAD/SIP004 only; not SS-2022 |
| Domain suffix route / block | Yes | Rule order matters, no automatic DNS interception |
| Hysteria2 / QUIC, SS-2022, REALITY, TUIC | No | Deliberately absent from UI, not silently downgraded |
| Network-wide TUN/TPROXY/DNS and Clash subscriptions | No | Requires separate firewall4, IPv6, DNS and rollback implementation |

These protocol connections have local Go integration tests. **Security audit and real-world, independent server compatibility are still release blockers.**

## Regression gates

- `go test -race ./...` loads the default UCI, parses mixed outbounds + routes and rejects invalid node references, public listeners, unsafe credential file permissions and unknown/unsupported protocols.
- `tests/luci_ui.test.js` executes the actual LuCI view in a mock form/rpc runtime and validates status, authentication, outbound editing options, route order and protocol-to-core parity.
- SDK workflow fetches official OpenWrt 25.12.6 qualcommax/ipq807x SDK with an explicit SHA256 before building actual APKs.

This is not a completed router image or a substitute for lab testing on an authorized device.
