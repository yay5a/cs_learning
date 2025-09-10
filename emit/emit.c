#include "emit/emit.h"
#include <arpa/inet.h>
#include <stdio.h>

static void print_mac(const uint8_t mac[6]) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
         mac[4], mac[5]);
}

void emit_text(const agg_t *agg) {
  printf("Unique MAC Addresses (%zu):\n", agg->mac_count);
  for (size_t i = 0; i < agg->mac_count; i++) {
    print_mac(agg->macs[i].mac);
    printf("\n");
  }
  printf("\nConversations (%zu):\n", agg->flow_count);
  char srcbuf[INET6_ADDRSTRLEN];
  char dstbuf[INET6_ADDRSTRLEN];
  for (size_t i = 0; i < agg->flow_count; i++) {
    const flow_key_t *f = &agg->flows[i];
    const void *src = f->src;
    const void *dst = f->dst;
    int af = AF_INET6;
    if (f->version == 4) {
      src = f->src + 12;
      dst = f->dst + 12;
      af = AF_INET;
    }
    inet_ntop(af, src, srcbuf, sizeof(srcbuf));
    inet_ntop(af, dst, dstbuf, sizeof(dstbuf));
    printf("%s -> %s proto %u sport %u dport %u\n", srcbuf, dstbuf, f->proto,
           f->sport, f->dport);
  }
  if (agg->dropped_macs) {
    printf("Dropped MACs: %llu\n", (unsigned long long)agg->dropped_macs);
  }
  if (agg->dropped_flows) {
    printf("Dropped flows: %llu\n", (unsigned long long)agg->dropped_flows);
  }
}
