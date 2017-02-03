MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -o errexit -o nounset -o pipefail -c
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.SUFFIXES:

CC := clang
CFLAGS ?= -Wall -g # -Werror
LDFLAGS ?= -shared -Wl,-z,defs -lpthread -lscion

CXX = clang++
# Add -DSCIONDEBUGPRINT below to enable debug printing. Doing so *will*
# break e.g. CircleCI since it is so spammy.
CXXFLAGS ?= $(CFLAGS) -fPIC -std=c++11 -Wthread-safety

LIB_DIR = ../../lib/libscion
INCLUDE_DIR = ./include
INC = -I$(LIB_DIR) -I$(INCLUDE_DIR)

SRCS = $(wildcard src/*.cpp) $(wildcard src/*.c)
TESTS = $(wildcard test/*.cpp)
OBJS = $(SRCS:src/%.cpp=build/%.o) $(SRCS:src/%.c=build/%.o) \
	$(TESTS:test/%.cpp=test/%.o)
STATIC = build/libssocket.a
DYNAMIC = build/libssocket.so
TARGETS = $(STATIC) $(DYNAMIC)
PREFIX ?= /usr/local

.PHONY: all
all: $(OBJS)

.PHONY: clean
clean:
	rm -f build/* *.d *.so *.a *.o .installstamp $(TARGETS)

# Compile .cpp files, while also automatically generating dependencies so they
# can be recompiled if any of the included header files changed.
-include *.d
build/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(USER_OPTS) $(INC) -MMD -c -o $@ $<

build/%.o: src/%.c
	$(CC) $(CFLAGS) $(USER_OPTS) $(INC) -MMD -c -o $@ $<

test/%.o: test/%.cpp
	$(CXX) $(CXXFLAGS) $(USER_OPTS) $(INC) -lgtest -MMD -o $@ $<


$(STATIC): $(OBJS)
	ar rcs $@ $(OBJS)

$(DYNAMIC): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS)


.PHONY: install
install: .installstamp

.installstamp: $(TARGETS)
	sudo cp $(TARGETS) $(PREFIX)/lib/
	sudo ldconfig
	touch .installstamp

.PHONY: uninstall
uninstall:
	$(foreach var,$(TARGETS),sudo rm -f $(PREFIX)/lib/$(var);)
	sudo ldconfig
	rm -f .installstamp
