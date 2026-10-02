CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=gnu11 -D_GNU_SOURCE
LDFLAGS = -lpcap
TARGET  = sim_ac

all: $(TARGET)

$(TARGET): sim_ac.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# target debug: hexdump sempre attivo, simboli per gdb
debug: sim_ac.c
	$(CC) -O0 -g -DDEBUG_HEXDUMP -Wall -o $(TARGET) $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all debug clean
