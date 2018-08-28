#   BSD LICENSE
#
#   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-clang

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
SHARED = libhsr.so
LIBABIVER := 1

# all source are stored in SRCS-y
SRCS-y := hsr_dpdk.c

#CFLAGS += -O3 -w
CFLAGS += -O3 -I$(S)/.. -I$(S)/../scion -Wall -fno-strict-aliasing -g
#CFLAGS += $(WERROR_FLAGS)

ifeq ($(D),1)
CFLAGS += -gdwarf-2 -O0
endif

EXTRA_LDFLAGS += -lscion -lrte_lpm

include $(RTE_SDK)/mk/rte.extshared.mk

.PHONY: doinstall
doinstall: .installstamp

PREFIX ?= /usr/local
build/$(SHARED): $(SHARED)
.installstamp: build/$(SHARED)
	@sudo -p "c/lib/hsr:install [sudo] password for %p: " true
	sudo cp build/$(SHARED) $(PREFIX)/lib/
	sudo ldconfig
	touch .installstamp

uninstall:
	@sudo -p "c/lib/hsr:uninstall [sudo] password for %p: " true
	sudo rm -r $(PREFIX)/lib/$(SHARED)
	sudo ldconfig
	rm -f .installstamp
