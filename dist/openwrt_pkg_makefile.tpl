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


# Dirty tricks here:
#
# This template is *expanded* while executing inside a sandbox
# (in <root_of_cache>/sandbox/<unique>/execroot/com_github_scionproto_scion). As a result, the %{component}
# substitution is relative to that path. It then gets copied to the global execroot
# (in  <root_of_cache>/execroot/com_github_scionproto_scion).
#
# However, the expanded template (i.e. Makefile) is *used* while executing outside
# any sandbox (in <root_of_cache> - why can't that be in execroot?). In addition, relative paths in
# Makefile are relative the Makefile's location (that's
# <root_of_cache/external/openwrt_SDK/scion/<pkgname>). So, we must
# "fix" the path. The very best would be to obtain the absolute current dir as part of or along
# with %{component}, but I don't know how to do that yet. So, hardcode the fix for now.
# 
# In addition bazel plays magic tricks with unionfs that cause ls ../../../../ to not be the
# same as cd'ing into it. cd gets us what we want. If you manage to understand it and have a
# better fix, go for it.
#
BASE := $(shell cd ../../../../execroot/com_github_scionproto_scion && pwd)

# Package preparation instructions; create the build directory. No source code. The package is built
# externally.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/execs
	mkdir -p $(PKG_BUILD_DIR)/initds
	mkdir -p $(PKG_BUILD_DIR)/configs
endef

# Package build instructions; just copy the assets from where they already are.
define Build/Compile
	cp $(BASE)/%{exec} $(PKG_BUILD_DIR)/execs/%{pkg}
	$(foreach i, %{initds}, cp $(BASE)/$(i) $(PKG_BUILD_DIR)/initds;)
	$(foreach c, %{configs}, cp $(BASE)/$(c) $(PKG_BUILD_DIR)/configs;)
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
