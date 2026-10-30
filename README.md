PCAP UDP telemetry header dump
Inspects classic PCAP Ethernet/IPv4 UDP headers without libpcap.
Build: make; regression tests: make test (Python 3).
Run: ./pcap_dump sample_capture.pcap 5000 6000
Filters either source or destination port, inclusive; defaults 5000-6000.
Reports timestamps, deltas between matches, captured lengths and ports.
Handles little/big endian captures with microsecond/nanosecond timestamps.
Skips fragmented IPv4, VLAN, IPv6 and non-UDP packets; rejects pcapng.
Accepts payload-truncated captures when all UDP headers are present.
Bounded 64 KiB packet storage; nonzero status on corrupt input. MIT.
