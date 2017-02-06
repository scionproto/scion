MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -o errexit -o nounset -o pipefail -c
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.SUFFIXES:

CC := clang
CFLAGS ?= -Wall -g -fPIC # -Werror
LDFLAGS ?= -Wl,-z,defs -L/usr/local/lib  # -shared
LDLIBS ?= -lpthread -lscion -lgtest

CXX = clang++
# Add -DSCIONDEBUGPRINT below to enable debug printing. Doing so *will*
# break e.g. CircleCI since it is so spammy.
CXXFLAGS ?= $(CFLAGS) -std=c++11 -Wthread-safety

LIB_DIR = ../../lib/libscion
HEADERS = ./include
INC = -I$(LIB_DIR) -I$(HEADERS)

BUILD = ./build
SOURCE = ./src
TEST = ./test


SRCS = $(wildcard $(SOURCE)/*.c*)
TESTS = $(wildcard $(TEST)/*.cpp)
OBJS = $(filter %.o, $(SRCS:$(SOURCE)/%.cpp=$(BUILD)/%.o) $(SRCS:$(SOURCE)/%.c=$(BUILD)/%.o) \
	$(TESTS:$(TEST)/%.cpp=$(BUILD)/%.o))
# STATIC = build/libssocket.a
# DYNAMIC = build/libssocket.so
# TARGETS = $(STATIC) $(DYNAMIC)
# PREFIX ?= /usr/local
# 
.PHONY: all
all: $(OBJS) $(TESTS:$(TEST)/%.cpp=$(BUILD)/%)

.PHONY: clean
clean:
	rm -f build/* .installstamp
 
# Compile .cpp files, while also automatically generating dependencies so they
# can be recompiled if any of the included header files changed.
-include $(BUILD)/*.d
$(BUILD)/%.o: $(SOURCE)/%.cpp
	$(CXX) $(CXXFLAGS) $(USER_OPTS) $(INC) -MMD -c -o $@ $<

-include $(BUILD)/*.d
$(BUILD)/%.o: $(SOURCE)/%.c
	$(CC) $(CFLAGS) $(USER_OPTS) $(INC) -MMD -c -o $@ $<

-include $(BUILD)/*.d
$(BUILD)/%.o: $(TEST)/%.cpp
	$(CXX) $(CXXFLAGS) $(USER_OPTS) $(INC) -MMD -c -o $@ $<

$(BUILD)/libsciond-test: $(BUILD)/libsciond-test.o $(BUILD)/sciondlib.o 
	$(CXX) $(USER_OPTS) $(LDFLAGS) $+ $(LDLIBS) -o $@

# 
# test/%.o: test/%.cpp
# 	$(CXX) $(CXXFLAGS) $(USER_OPTS) $(INC) -L/usr/local/lib -lgtest -lscion -MMD -o $@ build/sciondlib.o $<
# 
# 
# $(STATIC): $(OBJS)
# 	ar rcs $@ $(OBJS)
# 
# $(DYNAMIC): $(OBJS)
# 	$(CXX) $(LDFLAGS) -o $@ $(OBJS)
# 
# 
# .PHONY: install
# install: .installstamp
# 
# .installstamp: $(TARGETS)
# 	sudo cp $(TARGETS) $(PREFIX)/lib/
# 	sudo ldconfig
# 	touch .installstamp
# 
# .PHONY: uninstall
# uninstall:
# 	$(foreach var,$(TARGETS),sudo rm -f $(PREFIX)/lib/$(var);)
# 	sudo ldconfig
# 	rm -f .installstamp
