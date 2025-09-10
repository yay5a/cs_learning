#include "net/net.h"
#include <arpa/inet.h>
#include <string.h>

int net_parse(uint16_t ethertype, const uint8_t *data, size_t len,
              const net_limits_t *limits, net_packet_t *pkt) {
  memset(pkt, 0, sizeof(*pkt));
  if (ethertype == 0x0800) { // IPv4
    if (len < 20)
      return -1;
    uint8_t ihl = (data[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl)
      return -1;
    uint16_t total_len = ntohs(*(const uint16_t *)(data + 2));
    if (total_len < ihl || total_len > len)
      total_len = (uint16_t)len;
    pkt->version = 4;
    pkt->proto = data[9];
    memset(pkt->src, 0, 16);
    memset(pkt->dst, 0, 16);
    memcpy(pkt->src + 12, data + 12, 4);
    memcpy(pkt->dst + 12, data + 16, 4);
    pkt->payload = data + ihl;
    pkt->payload_len = total_len - ihl;
    return 0;
  } else if (ethertype == 0x86DD) { // IPv6
    if (len < 40)
      return -1;
    pkt->version = 6;
    uint8_t next = data[6];
    memcpy(pkt->src, data + 8, 16);
    memcpy(pkt->dst, data + 24, 16);
    const uint8_t *ptr = data + 40;
    size_t remain = len - 40;
    uint8_t count = 0;
    while ((next == 0 || next == 43 || next == 44 || next == 60) &&
           remain >= 8) {
      if (limits && limits->max_exthdrs && count >= limits->max_exthdrs) {
        return -1;
      }
      count++;
      uint8_t hdrlen = (uint8_t)((ptr[1] + 1) * 8);
      next = ptr[0];
      if (remain < hdrlen)
        return -1;
      ptr += hdrlen;
      remain -= hdrlen;
    }
    pkt->proto = next;
    pkt->payload = ptr;
    pkt->payload_len = remain;
    return 0;
  }
  return -1;
}
