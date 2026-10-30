# eproxy — extensible proxy project for OpenWrt

**State: functional prototype, not production-grade transparent routing.**

eproxy is independently maintained from the CPE-S10-SKY firmware. It replaces the *control plane* of OpenClash with its own OpenWrt UCI/procd package and LuCI UI, and begins a new multi-protocol proxy **core** in Go. It does **not** modify the Linux kernel or implement a full secure proxy client yet.

## Implemented and testable today

- Go standalone eproxy core; loopback-only listener defaults to `127.0.0.1:1080`.
- HTTP CONNECT tunnel over TCP, and SOCKS5 no-auth CONNECT to IPv4, IPv6 or domain endpoints. HTTP non-CONNECT requests are rejected.
- No public listener allowed (no-auth traffic must not be exposed to LAN/WAN).
- `eproxy` OpenWrt package (procd, UCI), `luci-app-eproxy` package (LuCI with restricted UCI ACL).
- GitHub Actions Go unit tests plus a real OpenWrt arm64 cross-compile job.

Future protocol components (Shadowsocks 2022, Trojan, VLESS, Hysteria2) have **interfaces/design placeholders only**. No cryptographic/protocol compatibility claims. Read [protocol roadmap](docs/protocol-roadmap.md).

## Native development

```sh
go test ./...
go run ./cmd/eproxy -listen 127.0.0.1:1080
curl --proxy http://127.0.0.1:1080 https://example.com
```

Only a local listener is supported until authentication and ACLs are reviewed. NO config/subscription/secrets are included.

## OpenWrt

OpenWrt package recipe is in `package/eproxy/Makefile`. It uses the OpenWrt feeds' Go toolchain definitions, installs `/usr/bin/eproxy`, `/etc/init.d/eproxy`, and `/etc/config/eproxy`. `luci-app-eproxy` supplies the UI and UCI ACL.

CI's OpenWrt cross-build is a compile/package test, **not a complete router firmware image**. Kernel NSS integration and full firmware build belong to [openwrt-cpe-s10-sky](https://github.com/jsw-teams/openwrt-cpe-s10-sky) and must pass additional hardware validation.

Public repository contains no device backup, ART, secrets, subscription URLs or personal configuration.

## Integration as a normal OpenWrt feed

In an authorized OpenWrt buildroot, configure the eproxy repository as its own feed:

```sh
echo 'src-git eproxy https://github.com/jsw-teams/eproxy.git' >> feeds.conf.default
./scripts/feeds update eproxy
# Pin feeds/eproxy to a reviewed commit before releasing any firmware.
./scripts/feeds install -p eproxy eproxy-core luci-app-eproxy
make defconfig
```

The eproxy package supports both the `src-git` feed source layout and CI-local source copying. These Go/LuCI packages are currently experimental and do not implement secure remote tunneling.
