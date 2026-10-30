# Standard OpenWrt package that installs LuCI assets and rpcd UCI ACL.
# Avoid relying on feed-local luci.mk path when built from a standalone feed.
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-eproxy
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-eproxy
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=eproxy experimental control panel
  DEPENDS:=+luci-base +eproxy-core
endef

define Build/Compile
endef

define Package/luci-app-eproxy/install
	$(INSTALL_DIR) $(1)/www
	$(CP) ./htdocs/. $(1)/www/
	$(CP) ./root/. $(1)/
endef

$(eval $(call BuildPackage,luci-app-eproxy))
