# eproxy advanced runtime and dual package support

## Runtime architecture

LuCI and UCI are shared by the eproxy native Go core and the managed sing-box engine. The native core handles its existing HTTP/SOCKS5/TLS transports. Selecting `engine=singbox` uses a separate, maintained sing-box binary for Hysteria2 over QUIC, VLESS REALITY, Shadowsocks-2022, encrypted TCP/UDP and optional LAN TUN routing.

The init script validates UCI, downloads configured HTTPS subscriptions with an atomic private cache, creates a 0600 sing-box configuration, executes `sing-box check`, and only then starts the engine via procd. Missing binaries or invalid configurations stop startup; unsupported traffic is not silently downgraded. Use sing-box 1.14.x with QUIC and uTLS support.

## DNS, IPv6 and LAN TUN

eproxy exposes the DNS strategy `prefer_ipv4`, `prefer_ipv6`, `ipv4_only` or `ipv6_only`, together with DNS server IP and certificate-verified DNS-over-HTTPS server name. Optional TUN uses IPv4 and IPv6 addresses, strict routing, nftables auto redirect and an explicit br-lan interface allowlist. The router WAN interface is not intentionally intercepted. Physical IPv6 and DNS leak testing is still required before enabling in production.

## HTTPS providers

Subscriptions support sing-box JSON outbound collections, supported proxy share URLs and Base64-encoded share URL lists. Each provider is HTTPS-only, limited in bytes and network time, refuses private-address resolution and follows no redirects. Remote content cannot import global routes, incoming listeners or executable scripts. Imported nodes are prefixed `sub_PROVIDER_NODE`, for use in default or domain-specific routing.

Clash YAML subscription conversion, provider health polling, and complete OpenClash rule compatibility are not yet implemented.

## Package formats

- OpenWrt 24.10.8 qualcommax/ipq807x uses **opkg / .ipk**.
- OpenWrt 25.12.6 qualcommax/ipq807x uses **apk / .apk**.
- GitHub Actions uses the official release's exact pinned SDK SHA-256 and its release-matched feeds for each target. Builds must pass before an installable package is claimed.
- IPK compatibility is not a guarantee of installation on unrelated QSDK Linux 5.4 firmware or a mismatched CPU/libc/kernel ABI.

Dependencies for advanced mode include a matching sing-box binary with QUIC/uTLS, ca-bundle, nftables and kmod-tun when TUN is enabled. eproxy is disabled by default. Do not commit private subscription URLs, credentials or device calibration data.

## What the tests prove

Unit tests, the LuCI view runtime contract, UCI/procd syntax checks, ARM64 cross-compilation and actual `sing-box check` with a pinned 1.14.0 binary exercise the generated advanced configuration. They do not replace third-party server interoperability, NSS/ECM coexistence, OpenWrt package installation on hardware, or live router recovery tests.
