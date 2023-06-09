#
# Copyright (C) 2021 - ntop.org and contributors
#

include $(TOPDIR)/rules.mk

PKG_NAME:=n2n
PKG_SOURCE_URL:=https://github.com/ntop/n2n.git
PKG_SOURCE_VERSION:=6937640a2bc24832af7fc4ed1658d6aef192f03b
PKG_VERSION:=3.0.0_git$(PKG_SOURCE_VERSION)
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

PKG_MAINTAINER:=Emanuele Faranda <faranda@ntop.org>
PKG_LICENSE:=GPL3
PKG_BUILD_PARALLEL:=1

# autogen fix
PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/n2n/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=N2N Peer-to-peer VPN
  URL:=http://www.ntop.org/n2n
  SUBMENU:=VPN
  DEPENDS+=+libcap
endef

define Package/n2n-edge
  $(call Package/n2n/Default)
  TITLE+= client (edge node)
  DEPENDS+=+kmod-tun
endef

define Package/n2n-supernode
  $(call Package/n2n/Default)
  TITLE+= server (supernode)
endef

define Package/n2n-edge/description
The client node for the N2N infrastructure
endef

define Package/n2n-supernode/description
The supernode for the N2N infrastructure
endef

define Build/Configure
	( cd $(PKG_BUILD_DIR); ./autogen.sh )
	$(call Build/Configure/Default)
endef

define Package/n2n-edge/conffiles
/etc/n2n/edge.conf
endef

define Package/n2n-edge/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/edge $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packages/openwrt/etc/init.d/edge $(1)/etc/init.d/edge
	$(INSTALL_DIR) $(1)/etc/n2n
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/packages/etc/n2n/edge.conf.sample $(1)/etc/n2n/edge.conf
endef

define Package/n2n-supernode/conffiles
/etc/n2n/supernode.conf
endef

define Package/n2n-supernode/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/supernode $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packages/openwrt/etc/init.d/supernode $(1)/etc/init.d/supernode
	$(INSTALL_DIR) $(1)/etc/n2n
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/packages/etc/n2n/supernode.conf.sample $(1)/etc/n2n/supernode.conf
endef

$(eval $(call BuildPackage,n2n-edge))
$(eval $(call BuildPackage,n2n-supernode))
