CC = gcc
CFLAGS = -O2 -Wall -Wextra -Werror -std=c99
all: pcap_dump
pcap_dump: pcap_dump.c
	$(CC) $(CFLAGS) -Iinclude pcap_dump.c -lm -o $@
clean:
	rm -f pcap_dump pcap_dump.exe *.o
.PHONY: all clean


test: pcap_dump
	python3 tests/test_cli.py
.PHONY: test
