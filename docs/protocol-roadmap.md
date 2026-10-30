# Multi-protocol architecture and compatibility gates

Core framework: transport and routing front end, versioned protocol handlers, DNS resolver, traffic accounting, outbound transport, lifecycle service. The current Go prototype multiplexes local HTTP CONNECT and SOCKS5 on one loopback port, with an intentionally small surface area.

Implemented: HTTP CONNECT, SOCKS5 CONNECT (no-auth, loopback only). These are **local client ingress protocols**, not encrypted remote proxy protocols.

Planned in separate audited milestones (NOT implemented):
1. Tailsafe transport, deadline, connection quotas, authentication, DNS policy, optional UDP ASSOCIATE (SOCKS5 UDP).
2. TLS-based Trojan outbound and Shadowsocks 2022 with verified crypto and published interoperability vectors.
3. VLESS outbound with tested transport variants; security is provided by TLS/REALITY or other specified transport, not VLESS itself.
4. Hysteria2 QUIC protocol with congestion and UDP tests; platform resource and license review.
5. Firewall4/nftables TUN integration with IPv6 kill switch, leak tests and network rollback.
6. LuCI policy groups, provider fetch with secret storage and signed pinned updates, observability.

For each protocol require: spec references and licensing, known-answer tests, client-server integration across version matrix, security review, fuzzing, IPv4+IPv6, runtime stress tests, and an explicit feature flag. Do not label unsupported variants supported.

NSS is a *router acceleration driver* and independent of eproxy protocol support; compatibility tests are required for transparent proxy flows.

## Implementation status update

A separate \`singbox\` engine now renders Hysteria2 (QUIC), VLESS REALITY
(uTLS-required), Shadowsocks-2022, HTTPS subscription providers, DNS-over-HTTPS,
TUN, IPv6 strategies and UDP handling. Configuration output is validated with
the pinned upstream sing-box binary in CI.

**Important dependency distinction:** These capabilities are powered by a
separately installed, ABI-compatible \`sing-box\` runtime, not by a newly
written eproxy-native QUIC/REALITY/SS-2022 implementation. The native Go engine
keeps its narrower protocol support.

The old OpenWrt 24.10.x target builds IPK, and the newer 25.12.x target builds
APK via separate SDK matrix jobs. They are not interchangeable across releases
or architectures. A successful SDK build verifies packaging only; modem, NSS,
TUN routing, DNS leak behavior, firewall4 rollback and real-server protocol
interoperability still require router test evidence.
