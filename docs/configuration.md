# Actual eproxy configuration and protocols

The daemon reads a private JSON file by `-config /etc/eproxy/config.json`. Its listen address is **loopback only**. There is no anonymous LAN/WAN ingress and no automatic subscription fetch.

**Implemented (TCP)**: inbound HTTP CONNECT and SOCKS5 CONNECT with optional local username/password; outbound direct, HTTP CONNECT (credentials only to loopback), SOCKS5, TLS Trojan, TLS VLESS (TCP, standard UUID authentication), and legacy Shadowsocks AEAD AES-256-GCM (SIP004, *not* Shadowsocks-2022). Domain suffix routing and block rules are supported, evaluated in JSON order. All encrypted outbounds require their specified key and verified TLS certificate (no TLS skip verify).

**Not implemented**: Hysteria2/QUIC, VLESS REALITY/XTLS, Shadowsocks-2022, TUIC, WireGuard, WebSocket/gRPC, encrypted outbound UDP relays, TUN/tproxy/nftables interception, remote subscription management, provider updates, rule providers, graphical secret editor and OpenClash profile migration.

Example direct-only config is `examples/direct.json`. Replace the outbound with your own private server settings for a real TLS proxy (do **not** commit passwords, UUIDs, server names, subscription tokens or CA private keys). Place config in `/etc/eproxy/config.json`, owner root and mode 0600, and enable the service in LuCI or via UCI. If disabled, no port opens.

## Example outbound shapes

```json
{
  "listen": "127.0.0.1:1080",
  "default_outbound": "secure",
  "outbounds": {
    "direct": {"type": "direct"},
    "secure": {
      "type": "trojan",
      "address": "your-server.example:443",
      "server_name": "your-server.example",
      "password": "REPLACE_PRIVATE_VALUE"
    }
  },
  "rules": [
    {"domain_suffix": "local.example", "outbound": "direct"}
  ]
}
```

For `vless` outbounds use `type: vless`, `uuid`, `server_name`, `address` and optionally `ca_file`. Only standard TCP over verified TLS is implemented (no REALITY). For `shadowsocks-aead`, use `address` and `password` containing a base64-encoded **32-byte PSK** for AES-256-GCM. This is legacy AEAD and not the 2022 variant. For `socks5` use `address`, and optional `username` and `password`, but the latter should only connect to a trusted loopback server (plaintext credentials). `http` can use optional credentials only when the upstream is loopback.

An OpenWrt management page will be available under LuCI's Services > eproxy, inheriting the router's future `/router/` path when LuCI is proven compatible. It only controls UCI enable/listen/path, not an unsafe arbitrary-shell endpoint.

## Testing and safety

```sh
go test -race -count=1 ./...
go vet ./...
go run ./cmd/eproxy -config examples/direct.json -check-config
```

Important: the built-in loopback proxy is **not** transparent routing, and thus cannot be considered a complete OpenClash replacement for LAN clients. Do not turn on a public listener to make it transparent: a separate audited TUN/firewall4 integration with authentication, DNS and IPv6 leak tests is necessary.

## Direct-only SOCKS5 UDP

The loopback SOCKS5 proxy implements UDP ASSOCIATE bound to its TCP association and a single UDP client source port. Direct outbound datagrams and domain block rules work. Unsupported FRAG packets and encrypted proxy outbounds are rejected/dropped. This does not implement Hysteria2 or remote UDP tunneling.
