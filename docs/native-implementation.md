# eproxy independent core ? implemented code paths

The original design borrows architecture concepts (typed outbounds, domain-based policies, secure DNS, tun/network separation) from public Mihomo and sing-box documentation, but not their source code or runtime logic.

## Compiled native Go implementation

- \`internal/proxy/server.go\`: loopback-only multiplexed SOCKS5/HTTP ingress and connection limits
- \`internal/proxy/outbound.go\`: native policy-based TCP dispatch, built-in direct/HTTP/SOCKS5/Trojan/VLESS/Shadowsocks AEAD
- \`internal/proxy/socks_udp.go\`: direct-only SOCKS5 UDP association with authenticated TCP-session lifetime
- \`internal/proxy/native_dns.go\`: independently written DNS-over-HTTPS client, manual RFC 1035 wire encoding/decoding with compression bounds and question validation, TLS bootstrap pinned by IP + SNI, IPv4/IPv6 family ordering, bounded cache and no plaintext/system fallback for direct targets
- \`internal/proxy/uci.go\`, \`cmd/eproxy/main.go\`: single-source UCI config validated before procd launch
- \`tests/luci_ui.test.js\`: UI-node-to-protocol parity

## Deliberate compatibility boundary

Hysteria2 needs HTTP/3 authentication and QUIC streams/datagrams, while REALITY and Shadowsocks-2022 need their respective audited crypto transports and extensive interoperability testing. These paths remain behind the **explicit** \`engine=singbox\` compatibility option in the current release. They are not mislabeled as native eproxy implementations.

Native direct DNS queries are encrypted. The current HTTP/SOCKS/Trojan/VLESS/SS outbound server hostnames may still use system resolver for their *proxy server bootstrap*; no global DNS leak-free guarantee is made. TUN, router-wide DNS, firewall and NSS acceleration still require target-specific device tests.

The release gate is \`go test -race ./...\` plus OpenWrt SDK artifact compilation on both 24.10 (IPK) and 25.12 (APK); real-router safety is an independent gate.

## Hysteria2 wire codec ? new original module

\`internal/protocol/hysteria2/wire.go\` contains independently written
RFC 9000 QUIC varints, the Hysteria2 TCP request/response stream framing, and
single-frame UDP datagram marshal/unmarshal with strict frame length and target
bounds. \`wire_test.go\` tests varint boundaries, the 0x401 TCP request ID,
stream payload preservation, round trips and malformed/fragmented datagrams.
The framing follows the public Hysteria2 protocol specification; no source
code was imported from Mihomo, sing-box or the Hysteria project.

This codec is **not yet a functioning Hysteria2 client**. It deliberately
does not implement QUIC, HTTP/3 authentication, congestion control, Salamander,
UDP fragment reassembly, or integration into a native outbound. Until these
are completed and independently interop-tested, \`engine=singbox\` remains
necessary for operational Hysteria2. The CI currently confirms the codec, not
that native Hysteria2 can connect to arbitrary servers.
