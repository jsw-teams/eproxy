include $(TOPDIR)/rules.mk

PKG_NAME:=eproxy-core
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1

GO_PKG:=github.com/jsw-teams/eproxy
GO_PKG_BUILD_PKG:=github.com/jsw-teams/eproxy/cmd/eproxy

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/eproxy-core
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=eproxy loopback-only protocol core
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Package/eproxy-core/conffiles
/etc/config/eproxy
endef

# Support both a standard OpenWrt src-link/src-git feed checkout and a
# CI-local package copy containing ./src/. Never download unpinned build code.
EPROXY_SOURCE_DIR:=$(if $(wildcard $(CURDIR)/src/go.mod),$(CURDIR)/src,$(abspath $(realpath $(CURDIR))/../..))

define Build/Prepare
	test -f $(EPROXY_SOURCE_DIR)/go.mod
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(EPROXY_SOURCE_DIR)/go.mod $(PKG_BUILD_DIR)/
	$(CP) $(EPROXY_SOURCE_DIR)/cmd $(EPROXY_SOURCE_DIR)/internal $(PKG_BUILD_DIR)/
	$(CP) $(EPROXY_SOURCE_DIR)/LICENSE $(PKG_BUILD_DIR)/
endef

define Package/eproxy-core/install
	$(call GoPackage/Package/Install/Bin,$(1))
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/eproxy.config $(1)/etc/config/eproxy
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/eproxy.init $(1)/etc/init.d/eproxy
endef

$(eval $(call GoBinPackage,eproxy-core))
$(eval $(call BuildPackage,eproxy-core))
