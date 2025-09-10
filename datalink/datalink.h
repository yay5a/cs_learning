#ifndef DATALINK_H
#define DATALINK_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t src[6];
  uint8_t dst[6];
  uint16_t ethertype;
} eth_frame_t;

int datalink_parse_ethernet(const uint8_t *data, size_t len, eth_frame_t *frame,
                            const uint8_t **payload, size_t *payload_len);

#endif
