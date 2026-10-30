# eproxy — 独立的 OpenWrt 多协议代理项目

**状态：正在实现与验证中的预发布软件。尚不能取代 OpenClash 的全部功能，也尚未批准用于生产路由。**

项目分成自己维护的 Go 代理核心、OpenWrt UCI/procd 服务包 `eproxy-core` 和 LuCI 前端 `luci-app-eproxy`。不使用 Mihomo 充当隐藏的代理后端；协议核心由 eproxy 自己实现。

## 已写入代码的功能

- 本地 HTTP CONNECT 和 SOCKS5 CONNECT 入口，严格限制为回环地址；两种入口均支持独立配置的账号密码认证。
- 出站：direct、HTTP CONNECT、SOCKS5、**Trojan over verified TLS**、**VLESS TCP over verified TLS**、**Shadowsocks legacy AEAD AES-256-GCM**。
- 路由规则：按域名后缀直连、代理或拒绝；支持 IPv4/IPv6 目标；并发连接上限、超时、配置严格校验、包含凭据的配置文件权限校验。
- Go 单元测试和本地互通测试；GitHub Actions 测试及 ARM64 编译，OpenWrt 官方源码上的 APK 交叉编译任务。
- 标准 `package/eproxy-core`、`package/luci-app-eproxy` 打包文件。服务默认禁用，除非准备好私有 `config.json` 并手动启用。

**协议范围必须区分清楚**：Trojan 是 TLS TCP，VLESS 是标准 TCP+TLS，Shadowsocks 是传统 SIP004 AEAD（并非 Shadowsocks-2022）。此处的实现尚需 CI 通过以及与其他独立客户端/服务器互通验证；写有对应代码不等于已经取得全部生产兼容性。

## 尚未实现

Hysteria2/QUIC、VLESS REALITY、SS-2022、TUIC、UDP ASSOCIATE、TUN/tproxy 透明代理、IPv6/DNS 防泄漏策略、订阅和节点管理、流量仪表盘、多用户 ACL、健康检查、订阅更新、故障回滚和 OpenClash 配置迁移。**没有这些功能就不能把 eproxy 称为完整 OpenClash 替代品。**

## 本地运行和测试

```sh
go test -race -count=1 ./...
go vet ./...
go run ./cmd/eproxy -config examples/direct.json -check-config
go run ./cmd/eproxy -config examples/direct.json
# In another terminal:
curl --proxy http://127.0.0.1:1080 https://example.com
```

JSON 配置结构、出站协议字段及私人凭据要求见 [配置说明](docs/configuration.md)。标准 OpenWrt 包和 LuCI 交叉编译位于 `package/` 与 `.github/workflows/`。

## 加入独立 OpenWrt feed

```sh
echo 'src-git eproxy https://github.com/jsw-teams/eproxy.git' >> feeds.conf.default
./scripts/feeds update eproxy
./scripts/feeds install -p eproxy eproxy-core luci-app-eproxy
# 正式发行之前需要锁定 eproxy 提交及 feeds 提交
make defconfig
```

eproxy 项目独立于 [CPE-S10 固件实验](https://github.com/jsw-teams/openwrt-cpe-s10-sky)。后者要求 NSS/ECM、5G MHI、无线 ART/BDF、LuCI 子路径 `/router/` 和串口恢复均通过实机验收才可刷写。

不在公共源码库发布订阅、代理凭据、设备校准数据、原始固件或私人系统配置。

## SOCKS5 UDP?????????????

??????? SOCKS5 UDP ASSOCIATE??????? TCP ????? UDP???? DNS?????????????? UDP ????????? UDP?Hysteria2/QUIC ? TUN ?????????? UDP ????????????
