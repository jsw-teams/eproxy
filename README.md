# eproxy — OpenWrt Multi-Protocol Manager

**Current status: pre-release. CI-tested advanced configuration, not production-validated router software.**

eproxy independently maintains a Go core, LuCI/UCI management interface, OpenWrt procd service, HTTPS subscription management, and sing-box configuration adapter.

### Capabilities

- Native Go: local HTTP and SOCKS5 proxy with credentials, direct UDP, HTTP/SOCKS5 outbounds, Trojan TLS, VLESS TCP TLS, legacy Shadowsocks AES-256-GCM.
- Managed sing-box advanced engine: **Hysteria2/QUIC, VLESS REALITY, Shadowsocks-2022, encrypted UDP, optional TUN**. QUIC and cryptography are provided by sing-box, not reimplemented inside eproxy.
- Shared LuCI/UCI controls for nodes, domain rules, subscriptions, DNS/IPv6, management status, credentials, and engine selection.
- Strictly HTTPS subscription sources: sing-box outbound JSON, supported share URLs, Base64 URL lists. Private cached credentials with rollback on failed refresh.
- DNS-over-HTTPS and configurable IPv4/IPv6 strategy; LAN-only TUN/auto-redirect with start-time dependency checks.
- Dual OpenWrt SDK workflow: 24.10.8 **IPK** (opkg) and 25.12.6 **APK** (apk), fixed release hashes and matching feeds.

### Quick validation

```sh
go test -race -count=1 ./...
go vet ./...
node tests/luci_ui.test.js
go run ./cmd/eproxy -uci package/eproxy-core/files/eproxy.config -check-config
```

See [advanced setup and legacy compatibility](docs/advanced-runtime.md) and [OpenWrt UI details](docs/openwrt-ui.md). The [SDK workflow](.github/workflows/sdk-package.yml) must pass before a package can be installed. Even a successful build does not guarantee compatibility with unrelated QSDK/OpenWrt kernel or hardware.

### Limitations

Hysteria2/REALITY/2022 compatibility requires an external sing-box runtime with QUIC/uTLS. Clash YAML imports, subscription auto-conversion of all vendor formats, comprehensive geo-rule providers, device-side IPv6 leak verification, TUN and NSS coexistence, and safe rollback testing remain unverified. eproxy is **not yet a drop-in production replacement for OpenClash**.

Source for Swaiot CPE-S10-SKY firmware: https://github.com/jsw-teams/openwrt-cpe-s10-sky. Device hardware validation and approved flashing are separate.

## Native eproxy DNS module (independent implementation)

The native Go engine now includes its own RFC 8484 DNS-over-HTTPS wire resolver. Direct TCP and direct SOCKS5 UDP destination names go through a pinned DoH IP with verified certificate, strict response parsing, family selection (\`prefer_ipv4\`, \`prefer_ipv6\`, \`ipv4_only\`, \`ipv6_only\`) and short-lived in-process caching. DNS failures **do not** fall back to operating-system UDP/53. DNS-related tests include malformed wire responses, address-family choices, local echo end-to-end and no-fallback behavior.

**Scope limitation:** The native resolver applies to *direct destination* resolution. Upstream proxy server bootstrap and network-wide DNS interception are separate concerns still requiring further implementation; \`engine=singbox\` is still needed for the advanced QUIC/REALITY/SS-2022 and TUN paths. This does not establish a fully independent replacement for those protocols yet. Do not flash an untested S10 image.
