# pcap_replay — DPDK pcap replayer used on the slave (traffic generator).
# Requires DPDK (pkg-config libdpdk) and libpcap. Output: build/pcap_replay
PKGCONF ?= pkg-config
CFLAGS  += -O3 $(shell $(PKGCONF) --cflags libdpdk) -DALLOW_EXPERIMENTAL_API
LDFLAGS += $(shell $(PKGCONF) --libs libdpdk) -lpcap

build/pcap_replay: pcap_replay.c | build
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

build:
	mkdir -p $@

clean:
	rm -rf build

.PHONY: clean
