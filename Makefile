NAME=score7
R2_PLUGIN_PATH=$(shell r2 -hh | grep R2_LIBR_PLUGINS | awk '{print $$2}')
CFLAGS=-g -fPIC $(shell pkg-config --cflags r_asm)
LDFLAGS=-shared $(shell pkg-config --libs r_asm)
OBJS=$(NAME).o
SO_EXT=$(shell uname | grep -q Darwin && echo dylib || echo so)
LIB=$(NAME).$(SO_EXT)

all: $(LIB)
	make -C score7_anal

clean:
	rm -f $(LIB) $(OBJS)
	make -C score7_anal clean

$(LIB): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(LIB)

install:
	cp -f $(LIB) $(R2_PLUGIN_PATH)
	make -C score7_anal install

uninstall:
	rm -f $(R2_PLUGIN_PATH)/$(LIB)
	make -C score7_anal install
