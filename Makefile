NAME=score7
R2_PLUGIN_PATH=$(shell r2 -H R2_USER_PLUGINS)
CFLAGS=-g -fPIC $(shell pkg-config --cflags r_arch)
LDFLAGS=-shared $(shell pkg-config --libs r_arch)
OBJS=$(NAME).o
SO_EXT=$(shell uname | grep -q Darwin && echo dylib || echo so)

.PHONY: all clean install uninstall

all: arch_$(NAME).$(SO_EXT)

arch_$(NAME).$(SO_EXT): arch_$(NAME).c
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o arch_$(NAME).$(SO_EXT) arch_$(NAME).c

clean:
	rm -f *.$(SO_EXT) *.o

install:
	mkdir -p $(R2_PLUGIN_PATH)
	cp -f arch_$(NAME).$(SO_EXT) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/arch_$(NAME).$(SO_EXT)
