# Makefile per compilare il modulo kernel xdp_rex

# Percorso al sorgente del kernel (modifica se serve)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Directory corrente (dove si trova questo Makefile)
PWD := $(shell pwd)

CFLAGS_xdp_regex_module.o := -g -O2 -Wall -Werror -fno-omit-frame-pointer -DKBUILD_MODNAME=\"module\" -D__KERNEL__ -DMODULE -mbtf

# Regola principale: build del modulo
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

insmod:
	sudo insmod xdp_regex_module.ko $(INSMOD_ARGS)   # INSMOD_ARGS=bench=1 for the microbenchmark

# Pulizia dei file compilati
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f xdp_prog.o xdp_prog_timing.o


# BPF programs calling the bpf_xdp_scan_bytes kfunc
bpf: xdp_prog.o xdp_prog_timing.o

xdp_prog.o: xdp_prog_kern_test.c rex.h
	clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c $< -o $@

xdp_prog_timing.o: xdp_prog_kern_timing.c rex.h
	clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c $< -o $@

.PHONY: all insmod clean bpf
