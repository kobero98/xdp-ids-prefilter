KDIR   ?= /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)
CLANG  ?= clang
CINC   := -I/usr/include -I/usr/include/x86_64-linux-gnu

obj-m := xdp_ac_module.o

CFLAGS_xdp_ac_module.o := -O2 -Wall -fno-omit-frame-pointer

.PHONY: all module bpf clean insmod rmmod

all: module bpf ac_build tools

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

bpf: xdp_prog_ac.o

xdp_prog_ac.o: xdp_prog_ac.c
	$(CLANG) -O2 -g -target bpf $(CINC) -c $< -o $@

ac_build: ac_build.c
	gcc -O2 -Wall -Wextra -std=c11 -o $@ $<

# userspace self-test / benchmarks (run on the same .acdb the kernel loads)
tools: ac_selftest ac_simfilter ac_winbench

ac_selftest: ac_selftest.c
	gcc -O2 -Wall -o $@ $<

ac_simfilter: ac_simfilter.c
	gcc -O2 -Wall -o $@ $< -lpcap

ac_winbench: ac_winbench.c
	gcc -O2 -Wall -o $@ $<

insmod: module
	sudo insmod xdp_ac_module.ko

rmmod:
	sudo rmmod xdp_ac_module

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f ac_build ac_selftest ac_simfilter ac_winbench patterns.acdb xdp_prog_ac.o
