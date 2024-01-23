include $(TOPDIR)/rules.mk

# Name, version and release number
# The name and version of your package are used to define the variable to point to the build directory of your package: $(PKG_BUILD_DIR)
PKG_NAME:=%{pkg}
PKG_VERSION:=%{version}
PKG_RELEASE:=%{release}

include $(INCLUDE_DIR)/package.mk

# Package definition; instructs on how and where our package will appear in the overall configuration menu ('make menuconfig')
define Package/%{pkg}
	SECTION:=scion
	CATEGORY:=SCION
	TITLE:=%{pkg}
endef

# Package description; a more verbose description on what our package does
define Package/%{pkg}/description
  A openwrt packaging of "SCION's %{pkg}".
endef

# This particular makefile gets expanded at
# <scion>/<execroot>/external/openwrt_SDK/scion/scion-router.
# The %{exec} (and other) paths that we get are relative to <scion>/<execroot>.
# So, in theory, at make time, that's just ../../../../%{exec}.
# However theory and practice diverge in an inconvenient way. Make somehow resolves bazel symlinks.
# As a result, when this make file is used, the current dir is <scion>/external/scion/scion_router.
# The execroot context has been lost, and with it our link to our %{exec} file. To work around that,
# we get the execroot absolute path from the command line. Defaulting to the theoretical value.
EXECROOT?="../../../.."

# Package preparation instructions; create the build directory. No source code. The package is built
# externally.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/execs
	mkdir -p $(PKG_BUILD_DIR)/initds
	mkdir -p $(PKG_BUILD_DIR)/configs
endef

# Package build instructions; just copy the assets from where they already are.
define Build/Compile
	cp $(EXECROOT)/%{exec} $(PKG_BUILD_DIR)/execs/%{pkg}
	$(foreach i, %{initds}, cp $(EXECROOT)/$(i) $(PKG_BUILD_DIR)/initds;)
	$(foreach c, %{configs}, cp $(EXECROOT)/$(c) $(PKG_BUILD_DIR)/configs;)
endef

# Package install instructions; create a directory inside the package to hold our executable, and then copy the executable we built previously into the folder
define Package/%{pkg}/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/scion
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/execs/%{pkg} $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/initds/* $(1)/etc/init.d
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/configs/* $(1)/etc/scion
endef

# This command is always the last, it uses the definitions and variables we give above in order to get the job done
$(eval $(call BuildPackage,%{pkg}))
