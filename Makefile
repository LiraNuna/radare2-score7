NAME=score7
R2_PLUGIN_PATH=$(shell r2 -H R2_USER_PLUGINS)
CFLAGS=-g -fPIC $(shell pkg-config --cflags r_asm r_anal)
LDFLAGS=-shared $(shell pkg-config --libs r_asm r_anal)
OBJS=$(NAME).o
SO_EXT=$(shell uname | grep -q Darwin && echo dylib || echo so)

.PHONY: all

all: asm/asm_$(NAME).$(SO_EXT) anal/anal_$(NAME).$(SO_EXT)

asm/asm_$(NAME).$(SO_EXT): asm/asm_$(NAME).c
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o asm/asm_$(NAME).$(SO_EXT) asm/asm_$(NAME).c

anal/anal_$(NAME).$(SO_EXT): anal/anal_$(NAME).c
	$(CC) $(CFLAGS) $(LDFLAGS) $(R2_CFLAGS) $(R2_LDFLAGS) -o anal/anal_$(NAME).$(SO_EXT) anal/anal_$(NAME).c

clean:
	rm -f */*.$(SO_EXT) */*.o

install:
	mkdir -p $(R2_PLUGIN_PATH)
	cp -f asm/asm_$(NAME).$(SO_EXT) $(R2_PLUGIN_PATH)
	cp -f anal/anal_$(NAME).$(SO_EXT) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/asm_$(NAME).$(SO_EXT)
	rm -f $(R2_PLUGIN_PATH)/anal_$(NAME).$(SO_EXT)
