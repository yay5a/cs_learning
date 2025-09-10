#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t version;
  uint8_t proto;
  uint8_t src[16];
  uint8_t dst[16];
  const uint8_t *payload;
  size_t payload_len;
} net_packet_t;

typedef struct {
  uint8_t max_exthdrs;
} net_limits_t;

int net_parse(uint16_t ethertype, const uint8_t *data, size_t len,
              const net_limits_t *limits, net_packet_t *pkt);

#endif
