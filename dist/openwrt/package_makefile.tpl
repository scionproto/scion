include $(TOPDIR)/rules.mk

# Name, version and release number
# The name and version of your package are used to define the variable to point to the build directory of your package: $(PKG_BUILD_DIR)
PKG_NAME:=%{pkg}
PKG_VERSION?=unknown
PKG_RELEASE?=unknown

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
# <scion>/<execroot>/external/openwrt_<target>_SDK/scion/scion-<component>.
# The %{exec} (and other) paths that we get are relative to <scion>/<execroot>.
# So, in theory, at make time, that's just ../../../../%{exec}.
# However theory and practice diverge in an inconvenient way. Make somehow resolves bazel symlinks.
# As a result, when this make file is used, the current dir is <scion>/external/openwrt_<target>_SDK/scion/scion-<component>.
# The execroot context has been lost, and with it our link to our %{exec} file. To work around that,
# we get the execroot absolute path from the command line. Defaulting to the theoretical value.
EXECROOT?="../../../.."

# Package preparation instructions; create the build directory. No source code. The package is built
# externally.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/execs
	mkdir -p $(PKG_BUILD_DIR)/initds
	mkdir -p $(PKG_BUILD_DIR)/configs
	mkdir -p $(PKG_BUILD_DIR)/overrides
endef

# Package build instructions; just copy the assets from where they already are.
# For files that go into a shared directory, such as /usr/bin/ or /etc/init.d, make sure
# that they are prefixed with "scion-". Remove any redundant scion-scion as needed.
define Build/Compile
	for e in %{execs}; do \
	      	bname="scion-$$$$(basename $$$${e} .gunzip)"; \
		sname=$$$${bname/scion-scion/scion}; \
		cp -f $(EXECROOT)/$$$${e} $(PKG_BUILD_DIR)/execs/$$$${sname}; \
	done
	for i in %{initds}; do \
	      	bname="scion-$$$$(basename $$$${i})"; \
		sname=$$$${bname/scion-scion/scion}; \
		cp -f $(EXECROOT)/$$$${i} $(PKG_BUILD_DIR)/initds/$$$${sname}; \
	done
	ABS_BUILD_DIR="$$$$(cd $(PKG_BUILD_DIR) && pwd)"; \
	cd $(EXECROOT)/%{configsroot} && \
	for c in %{configs}; do \
		cp -f --parent $$$${c##%{configsroot}/} $$$${ABS_BUILD_DIR}/configs/; \
	done && \
	cd $(EXECROOT)/%{overridesroot} && \
	for c in %{overrides}; do \
		cp -f --parent $$$${c##%{overridesroot}/} $$$${ABS_BUILD_DIR}/overrides/; \
	done
endef

# Package install instructions; create a directory inside the package to hold our executable, and then copy the executable we built previously into the folder
define Package/%{pkg}/install
	$(INSTALL_DIR) $(1)/usr/bin
	if [ -n "$$$$(ls -A $(PKG_BUILD_DIR)/execs)" ]; then $(INSTALL_BIN) $(PKG_BUILD_DIR)/execs/* $(1)/usr/bin; fi
	$(INSTALL_DIR) $(1)/etc/init.d
	if [ -n "$$$$(ls -A $(PKG_BUILD_DIR)/initds)" ]; then $(INSTALL_BIN) $(PKG_BUILD_DIR)/initds/* $(1)/etc/init.d; fi
	INS_DIR="$$$$(cd $(1) && pwd)"; \
	cd $(PKG_BUILD_DIR)/configs && \
	find . -type d -print0 | xargs -0 -I{} $(INSTALL_DIR) $$$${INS_DIR}/etc/scion/{} && \
	find . -type f -print0 | xargs -0 -I{} $(INSTALL_CONF) {} $$$${INS_DIR}/etc/scion/{}.default && \
	cd $(PKG_BUILD_DIR)/overrides && \
	find . -type d -print0 | xargs -0 -I{} $(INSTALL_DIR) $$$${INS_DIR}/etc/scion/{} && \
	find . -type f -print0 | xargs -0 -I{} $(INSTALL_CONF) {} $$$${INS_DIR}/etc/scion/{}
endef

# This command is always the last, it uses the definitions and variables we give above in order to get the job done
$(eval $(call BuildPackage,%{pkg}))
