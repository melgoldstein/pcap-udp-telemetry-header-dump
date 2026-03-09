#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct { uint32_t magic; uint16_t major, minor;
    uint32_t zone, accuracy, snaplen, network; } CaptureHeader;
typedef struct { uint32_t seconds, fraction, captured, original; } PacketHeader;
#pragma pack(pop)

static uint32_t word(const void *address, int little) {
    const unsigned char *octets = address;
    if (little) return (uint32_t)octets[0] | (uint32_t)octets[1] << 8 |
        (uint32_t)octets[2] << 16 | (uint32_t)octets[3] << 24;
    return (uint32_t)octets[3] | (uint32_t)octets[2] << 8 |
        (uint32_t)octets[1] << 16 | (uint32_t)octets[0] << 24;
}
static unsigned network16(const unsigned char *octets) {
    return (unsigned)octets[0] * 256 + octets[1];
}
static int port(const char *argument, unsigned *value) {
    char *end;
    unsigned long parsed = strtoul(argument, &end, 10);
    if (!*argument || *end || parsed > 65535) return 0;
    *value = (unsigned)parsed;
    return 1;
}
int main(int argc, char **argv) {
    unsigned lower = 5000, upper = 6000;
    if ((argc != 2 && argc != 4) ||
        (argc == 4 && (!port(argv[2], &lower) || !port(argv[3], &upper))) ||
        lower > upper) {
        fprintf(stderr, "usage: pcap_dump capture.pcap [first_port last_port]\n");
        return 2;
    }
    FILE *capture = fopen(argv[1], "rb");
    if (!capture) { perror(argv[1]); return 1; }
    CaptureHeader header = {0};
    int failed = fread(&header, 1, sizeof header, capture) != sizeof header;
    uint32_t magic = failed ? 0 : word(&header.magic, 1);
    int little = magic == 0xa1b2c3d4 || magic == 0xa1b23c4d;
    int nano = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
    unsigned char *version = (unsigned char *)&header.major;
    int version_ok = little ? version[0]==2 && version[1]==0 && version[2]==4 && version[3]==0
                            : version[0]==0 && version[1]==2 && version[2]==0 && version[3]==4;
    if (!version_ok || (!little && magic != 0xd4c3b2a1 && magic != 0x4d3cb2a1) ||
        word(&header.network, little) != 1) failed = 1;
    unsigned char packet[65536];
    PacketHeader record;
    double previous = 0;
    unsigned matches = 0;
    puts("timestamp_s,delta_s,captured_bytes,source_port,destination_port");
    while (!failed) {
        size_t read_count = fread(&record, 1, sizeof record, capture);
        if (!read_count) break;
        if (read_count != sizeof record) { failed = 1; break; }
        uint32_t length = word(&record.captured, little);
        uint32_t fraction = word(&record.fraction, little);
        if (length > sizeof packet || length > word(&header.snaplen, little) ||
            length > word(&record.original, little) ||
            fraction >= (nano ? 1000000000u : 1000000u) ||
            fread(packet, 1, length, capture) != length) { failed = 1; break; }
        if (length < 34 || network16(packet + 12) != 0x0800) continue;
        unsigned char *ip = packet + 14;
        unsigned ihl = (ip[0] & 15) * 4, total = network16(ip + 2);
        if (ip[0] >> 4 != 4 || ihl < 20 || total < ihl + 8 ||
            length < 14 + ihl + 8 || ip[9] != 17 ||
            (network16(ip + 6) & 0x3fff)) continue;
        unsigned char *udp = ip + ihl;
        unsigned source = network16(udp), destination = network16(udp + 2);
        unsigned udp_length = network16(udp + 4);
        if (udp_length < 8 || udp_length > total - ihl) continue;
        if (!((source >= lower && source <= upper) ||
              (destination >= lower && destination <= upper))) continue;
        double timestamp = word(&record.seconds, little) +
            fraction / (nano ? 1e9 : 1e6);
        printf("%.9f,%.9f,%u,%u,%u\n", timestamp,
            matches ? timestamp - previous : 0, length, source, destination);
        previous = timestamp;
        ++matches;
    }
    failed = failed || ferror(capture);
    fclose(capture);
    if (failed) fprintf(stderr, "invalid or truncated classic Ethernet PCAP\n");
    return failed;
}
