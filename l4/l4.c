#include "l4/l4.h"
#include <arpa/inet.h>

int l4_parse_ports(uint8_t proto, const uint8_t *data, size_t len,
                   l4_ports_t *ports) {
  if (proto != 6 && proto != 17)
    return -1;
  if (len < 4)
    return -1;
  ports->src = ntohs(*(const uint16_t *)data);
  ports->dst = ntohs(*(const uint16_t *)(data + 2));
  return 0;
}
