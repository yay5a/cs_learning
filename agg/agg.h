#ifndef AGG_H
#define AGG_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t version;
  uint8_t src[16];
  uint8_t dst[16];
  uint8_t proto;
  uint16_t sport;
  uint16_t dport;
} flow_key_t;

typedef struct {
  uint8_t mac[6];
} mac_key_t;

typedef struct {
  size_t max_macs;
  size_t max_flows;
  size_t mac_count;
  size_t flow_count;
  uint64_t dropped_macs;
  uint64_t dropped_flows;
  mac_key_t *macs;
  flow_key_t *flows;
} agg_t;

void agg_init(agg_t *agg, size_t max_macs, size_t max_flows);
void agg_free(agg_t *agg);
void agg_add_mac(agg_t *agg, const uint8_t mac[6]);
void agg_add_flow(agg_t *agg, const flow_key_t *key);

#endif
