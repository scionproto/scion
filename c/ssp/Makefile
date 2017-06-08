.PHONY: all clean install uninstall

CXX = clang++
# Add -DSCIONDEBUGPRINT below to enable debug printing. Doing so *will*
# break e.g. CircleCI since it is so spammy.
CXXFLAGS ?= -Wall -Werror -g -fPIC -std=c++11 -Wthread-safety
LDFLAGS ?= -shared -Wl,-z,defs -lpthread -lscion

LIB_DIR = ../lib/scion
INC = -I$(LIB_DIR)

SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o)
STATIC = libssocket.a
DYNAMIC = libssocket.so
TARGETS = $(STATIC) $(DYNAMIC)
PREFIX ?= /usr/local

all: $(TARGETS)

clean:
	rm -f *.d *.so *.a *.o .installstamp $(TARGETS)

# Compile .cpp files, while also automatically generating dependencies so they
# can be recompiled if any of the included header files changed.
-include *.d
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(USER_OPTS) $(INC) -MMD -c -o $@ $<

$(STATIC): $(OBJS)
	ar rcs $@ $(OBJS)

$(DYNAMIC): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS)

install: .installstamp

.installstamp: $(TARGETS)
	sudo cp $(TARGETS) $(PREFIX)/lib/
	sudo ldconfig
	touch .installstamp

uninstall:
	$(foreach var,$(TARGETS),sudo rm -f $(PREFIX)/lib/$(var);)
	sudo ldconfig
	rm -f .installstamp
