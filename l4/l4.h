#ifndef L4_H
#define L4_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint16_t src;
  uint16_t dst;
} l4_ports_t;

int l4_parse_ports(uint8_t proto, const uint8_t *data, size_t len,
                   l4_ports_t *ports);

#endif
