#include "pcap_io/pcap_io.h"
#include <stdio.h>
#include <string.h>

int pcap_io_run(const char *file, const pcap_limits_t *limits, pcap_cb_t cb,
                void *user, pcap_stats_t *stats) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pc = pcap_open_offline(file, errbuf);
  if (!pc) {
    fprintf(stderr, "%s\n", errbuf);
    return -1;
  }
  if (stats) {
    memset(stats, 0, sizeof(*stats));
  }
  const u_char *data;
  struct pcap_pkthdr *hdr;
  int ret;
  while ((ret = pcap_next_ex(pc, &hdr, &data)) == 1) {
    if (stats) {
      if (limits) {
        if (limits->max_pkts && stats->pkt_count >= limits->max_pkts) {
          break;
        }
        if (limits->max_bytes &&
            stats->byte_count + hdr->caplen > limits->max_bytes) {
          break;
        }
      }
      stats->pkt_count++;
      stats->byte_count += hdr->caplen;
    }
    if (cb(hdr, (const uint8_t *)data, user) != 0) {
      break;
    }
  }
  if (stats) {
    struct pcap_stat ps;
    if (pcap_stats(pc, &ps) == 0) {
      stats->dropped = ps.ps_drop;
    }
  }
  pcap_close(pc);
  return 0;
}
