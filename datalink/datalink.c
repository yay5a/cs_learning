#include "datalink/datalink.h"
#include <string.h>

int datalink_parse_ethernet(const uint8_t *data, size_t len, eth_frame_t *frame,
                            const uint8_t **payload, size_t *payload_len) {
  if (len < 14)
    return -1;
  memcpy(frame->dst, data, 6);
  memcpy(frame->src, data + 6, 6);
  uint16_t ethertype = (uint16_t)(data[12] << 8 | data[13]);
  size_t offset = 14;
  if (ethertype == 0x8100) {
    if (len < 18)
      return -1;
    ethertype = (uint16_t)(data[16] << 8 | data[17]);
    offset = 18;
  }
  frame->ethertype = ethertype;
  if (len < offset)
    return -1;
  *payload = data + offset;
  *payload_len = len - offset;
  return 0;
}
