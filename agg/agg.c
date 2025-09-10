#include "agg/agg.h"
#include <stdlib.h>
#include <string.h>

void agg_init(agg_t *agg, size_t max_macs, size_t max_flows) {
  agg->max_macs = max_macs;
  agg->max_flows = max_flows;
  agg->mac_count = agg->flow_count = 0;
  agg->dropped_macs = agg->dropped_flows = 0;
  agg->macs = (mac_key_t *)malloc(max_macs * sizeof(mac_key_t));
  agg->flows = (flow_key_t *)malloc(max_flows * sizeof(flow_key_t));
}

void agg_free(agg_t *agg) {
  free(agg->macs);
  free(agg->flows);
}

static int mac_equal(const uint8_t a[6], const uint8_t b[6]) {
  return memcmp(a, b, 6) == 0;
}

void agg_add_mac(agg_t *agg, const uint8_t mac[6]) {
  for (size_t i = 0; i < agg->mac_count; i++) {
    if (mac_equal(agg->macs[i].mac, mac)) {
      return;
    }
  }
  if (agg->mac_count >= agg->max_macs) {
    agg->dropped_macs++;
    return;
  }
  memcpy(agg->macs[agg->mac_count].mac, mac, 6);
  agg->mac_count++;
}

static int flow_equal(const flow_key_t *a, const flow_key_t *b) {
  return a->version == b->version && a->proto == b->proto &&
         a->sport == b->sport && a->dport == b->dport &&
         memcmp(a->src, b->src, 16) == 0 && memcmp(a->dst, b->dst, 16) == 0;
}

void agg_add_flow(agg_t *agg, const flow_key_t *key) {
  for (size_t i = 0; i < agg->flow_count; i++) {
    if (flow_equal(&agg->flows[i], key)) {
      return;
    }
  }
  if (agg->flow_count >= agg->max_flows) {
    agg->dropped_flows++;
    return;
  }
  agg->flows[agg->flow_count] = *key;
  agg->flow_count++;
}
