CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g
LDFLAGS = -lpcap

SRCS = main.c pcap_analyzer.c protocol_detector.c \
       rules_parser.c pattern_extractor.c hyperscan_formatter.c

OBJS = $(SRCS:.c=.o)
TARGET = analyzer

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

pcap_hs_scan: pcap_hs_scan.c
	$(CC) -O2 -o $@ $< -lpcap -lhs -lstdc++ -lm -I/usr/local/include

clean:
	rm -f $(OBJS) $(TARGET) patterns.hs filtered.rules pcap_hs_scan

.PHONY: all clean pcap_hs_scan
