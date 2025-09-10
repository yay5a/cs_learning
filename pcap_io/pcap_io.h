#ifndef PCAP_IO_H
#define PCAP_IO_H

#include <stdint.h>
#include <sys/types.h>
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;
#include <pcap/pcap.h>

typedef struct {
  uint64_t max_pkts;
  uint64_t max_bytes;
} pcap_limits_t;

typedef struct {
  uint64_t pkt_count;
  uint64_t byte_count;
  uint64_t dropped;
} pcap_stats_t;

typedef int (*pcap_cb_t)(const struct pcap_pkthdr *hdr, const uint8_t *data,
                         void *user);

int pcap_io_run(const char *file, const pcap_limits_t *limits, pcap_cb_t cb,
                void *user, pcap_stats_t *stats);

#endif
