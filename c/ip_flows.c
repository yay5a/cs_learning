// pcap_flows.c
// Compile: gcc -O2 -Wall pcap_flows.c -o pcap_flows
// Usage:   ./pcap_flows <file.pcap>

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---------------- PCAP structs ----------------
#pragma pack(push, 1)
typedef struct {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} pcap_glob_t;

typedef struct {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len; // captured length
  uint32_t orig_len; // on-the-wire length
} pcap_pkt_t;
#pragma pack(pop)

// ---------------- Minimal hash map ----------------
typedef struct Flow {
  char key[256];     // "v4|src|dst|proto|sport|dport" or
                     // "v6|src|dst|proto|sport|dport"
  uint64_t count;    // packet count
  struct Flow *next; // chaining
} Flow;

typedef struct AddrNode {
  char addr[INET6_ADDRSTRLEN];
  struct AddrNode *next;
} AddrNode;

#define FLOW_BUCKETS 262144u
#define ADDR_BUCKETS 65536u

static Flow *flow_tbl[FLOW_BUCKETS];
static AddrNode *v4set[ADDR_BUCKETS], *v6set[ADDR_BUCKETS];

static uint32_t djb2(const char *s) {
  uint32_t h = 5381u;
  for (; *s; ++s)
    h = ((h << 5) + h) ^ (uint8_t)(*s);
  return h;
}

static uint32_t djb2_bytes(const uint8_t *p, size_t n) {
  uint32_t h = 5381u;
  for (size_t i = 0; i < n; i++)
    h = ((h << 5) + h) ^ p[i];
  return h;
}

static void addrset_add(AddrNode **buckets, const char *addr) {
  uint32_t h = djb2(addr) & (ADDR_BUCKETS - 1);
  for (AddrNode *n = buckets[h]; n; n = n->next)
    if (!strcmp(n->addr, addr))
      return;
  AddrNode *n = (AddrNode *)malloc(sizeof(*n));
  strncpy(n->addr, addr, sizeof(n->addr));
  n->addr[sizeof(n->addr) - 1] = 0;
  n->next = buckets[h];
  buckets[h] = n;
}

static uint64_t addrset_count(AddrNode **buckets) {
  uint64_t c = 0;
  for (size_t i = 0; i < ADDR_BUCKETS; i++)
    for (AddrNode *n = buckets[i]; n; n = n->next)
      c++;
  return c;
}

static Flow *flow_upsert(const char *key) {
  uint32_t h = djb2(key) & (FLOW_BUCKETS - 1);
  for (Flow *f = flow_tbl[h]; f; f = f->next)
    if (!strcmp(f->key, key)) {
      f->count++;
      return f;
    }
  Flow *f = (Flow *)calloc(1, sizeof(*f));
  strncpy(f->key, key, sizeof(f->key));
  f->key[sizeof(f->key) - 1] = 0;
  f->count = 1;
  f->next = flow_tbl[h];
  flow_tbl[h] = f;
  return f;
}

typedef struct {
  char *key;
  uint64_t count;
} Row;

static int cmp_row_desc(const void *a, const void *b) {
  const Row *x = a, *y = b;
  if (x->count < y->count)
    return 1;
  if (x->count > y->count)
    return -1;
  return strcmp(x->key, y->key);
}

static Row *collect_rows(size_t *out_n) {
  size_t cap = 1024, n = 0;
  Row *rows = (Row *)malloc(cap * sizeof(Row));
  for (size_t i = 0; i < FLOW_BUCKETS; i++) {
    for (Flow *f = flow_tbl[i]; f; f = f->next) {
      if (n == cap) {
        cap *= 2;
        rows = (Row *)realloc(rows, cap * sizeof(Row));
      }
      rows[n].key = strdup(f->key);
      rows[n].count = f->count;
      n++;
    }
  }
  *out_n = n;
  qsort(rows, n, sizeof(Row), cmp_row_desc);
  return rows;
}

// ---------------- Utilities ----------------
static uint16_t bswap16(uint16_t x) { return (x >> 8) | (x << 8); }
static uint32_t bswap32(uint32_t x) {
  return (x >> 24) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | (x << 24);
}

// IPv6 extension header walk (very basic)
static bool skip_ipv6_ext(const uint8_t *buf, size_t len, size_t *off,
                          uint8_t *nh) {
  // Extension headers set
  while (*nh == 0 || *nh == 43 || *nh == 44 || *nh == 50 || *nh == 51 ||
         *nh == 60) {
    if (*off + 2 > len)
      return false;
    uint8_t hdrlen = buf[*off + 1];
    size_t bytes = (size_t)(hdrlen + 1) * 8;
    *nh = buf[*off]; // next header field is at current start
    *off += bytes;
    if (*off > len)
      return false;
  }
  return true;
}

// ---------------- Parser ----------------
int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <file.pcap>\n", argv[0]);
    return 2;
  }
  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    perror("fopen");
    return 1;
  }

  pcap_glob_t gh;
  if (fread(&gh, sizeof(gh), 1, f) != 1) {
    fprintf(stderr, "bad global header\n");
    return 1;
  }

  bool need_swap = false;
  if (gh.magic_number == 0xa1b2c3d4u)
    need_swap = false; // native
  else if (gh.magic_number == 0xd4c3b2a1u)
    need_swap = true; // swapped
  else {
    fprintf(stderr, "unsupported pcap magic 0x%08x\n", gh.magic_number);
    return 1;
  }

  uint32_t linktype = need_swap ? bswap32(gh.network) : gh.network;
  if (linktype != 1) {
    fprintf(stderr, "only LINKTYPE_ETHERNET(1) supported, got %u\n", linktype);
    return 1;
  }

  uint64_t total_pkts = 0, parsed_pkts = 0;

  for (;;) {
    pcap_pkt_t ph;
    if (fread(&ph, sizeof(ph), 1, f) != 1)
      break;

    uint32_t incl = need_swap ? bswap32(ph.incl_len) : ph.incl_len;
    if (incl == 0) {
      continue;
    }

    // Read packet bytes
    uint8_t *buf = (uint8_t *)malloc(incl);
    if (!buf) {
      fprintf(stderr, "OOM\n");
      return 1;
    }
    if (fread(buf, incl, 1, f) != 1) {
      free(buf);
      break;
    }
    total_pkts++;

    size_t off = 0;
    if (incl < 14) {
      free(buf);
      continue;
    }
    uint16_t ethertype = (buf[12] << 8) | buf[13];
    off = 14;

    // VLAN 802.1Q tag
    if (ethertype == 0x8100) {
      if (incl < off + 4) {
        free(buf);
        continue;
      }
      ethertype = (buf[off + 2] << 8) | buf[off + 3];
      off += 4;
    }

    if (ethertype == 0x0800) { // IPv4
      if (incl < off + 20) {
        free(buf);
        continue;
      }
      uint8_t ihl = (buf[off] & 0x0F) * 4;
      if (incl < off + ihl) {
        free(buf);
        continue;
      }
      uint8_t proto = buf[off + 9];

      char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, buf + off + 12, src, sizeof(src));
      inet_ntop(AF_INET, buf + off + 16, dst, sizeof(dst));
      addrset_add(v4set, src);
      addrset_add(v4set, dst);

      uint16_t sport = 0, dport = 0;
      size_t l4 = off + ihl;
      if (proto == 6 || proto == 17) { // TCP or UDP
        if (incl >= l4 + 4) {
          sport = (buf[l4] << 8) | buf[l4 + 1];
          dport = (buf[l4 + 2] << 8) | buf[l4 + 3];
        }
      } else {
        free(buf);
        parsed_pkts++;
        continue;
      }

      char key[256];
      snprintf(key, sizeof(key), "v4|%s|%s|%u|%u|%u", src, dst, (unsigned)proto,
               (unsigned)sport, (unsigned)dport);
      flow_upsert(key);
      parsed_pkts++;
    } else if (ethertype == 0x86DD) { // IPv6
      if (incl < off + 40) {
        free(buf);
        continue;
      }
      uint8_t nh = buf[off + 6];
      size_t ip6off = off + 40;

      // Address strings
      char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, buf + off + 8, src, sizeof(src));
      inet_ntop(AF_INET6, buf + off + 24, dst, sizeof(dst));
      addrset_add(v6set, src);
      addrset_add(v6set, dst);

      // walk basic extensions
      if (!skip_ipv6_ext(buf, incl, &ip6off, &nh)) {
        free(buf);
        continue;
      }

      uint16_t sport = 0, dport = 0;
      if (nh == 6 || nh == 17) {
        if (incl >= ip6off + 4) {
          sport = (buf[ip6off] << 8) | buf[ip6off + 1];
          dport = (buf[ip6off + 2] << 8) | buf[ip6off + 3];
        }
      } else {
        free(buf);
        parsed_pkts++;
        continue;
      }

      char key[256];
      snprintf(key, sizeof(key), "v6|%s|%s|%u|%u|%u", src, dst, (unsigned)nh,
               (unsigned)sport, (unsigned)dport);
      flow_upsert(key);
      parsed_pkts++;
    }
    // else: non-IP, ignore

    free(buf);
  }

  // Collect & sort flows
  size_t nrows = 0;
  Row *rows = collect_rows(&nrows);

  // Print summary
  printf("=== Summary ===\n");
  printf("Total packets (in file): %" PRIu64 "\n", total_pkts);
  printf("Parsed IP packets (TCP/UDP): %" PRIu64 "\n", parsed_pkts);
  printf("Unique IPv4 addresses: %" PRIu64 "\n", addrset_count(v4set));
  printf("Unique IPv6 addresses: %" PRIu64 "\n", addrset_count(v6set));
  printf("\n");

  // Print flows (IPv4 then IPv6), sorted by packet count desc
  printf("=== IPv4 flows by packet count ===\n");
  for (size_t i = 0; i < nrows; i++) {
    if (rows[i].key[0] == 'v' && rows[i].key[1] == '4') {
      // key format: v4|src|dst|proto|sport|dport
      char src[64], dst[64];
      unsigned proto, sport, dport;
      if (sscanf(rows[i].key, "v4|%63[^|]|%63[^|]|%u|%u|%u", src, dst, &proto,
                 &sport, &dport) == 5) {
        const char *pname = (proto == 6) ? "TCP" : (proto == 17) ? "UDP" : "?";
        printf("%12" PRIu64 "  %s → %s  %s  %u → %u\n", rows[i].count, src, dst,
               pname, sport, dport);
      }
    }
  }
  printf("\n=== IPv6 flows by packet count ===\n");
  for (size_t i = 0; i < nrows; i++) {
    if (rows[i].key[0] == 'v' && rows[i].key[1] == '6') {
      // key format: v6|src|dst|proto|sport|dport
      char src[80], dst[80];
      unsigned proto, sport, dport;
      if (sscanf(rows[i].key, "v6|%79[^|]|%79[^|]|%u|%u|%u", src, dst, &proto,
                 &sport, &dport) == 5) {
        const char *pname = (proto == 6) ? "TCP" : (proto == 17) ? "UDP" : "?";
        printf("%12" PRIu64 "  [%s] → [%s]  %s  %u → %u\n", rows[i].count, src,
               dst, pname, sport, dport);
      }
    }
  }

  // Cleanup
  for (size_t i = 0; i < nrows; i++)
    free(rows[i].key);
  free(rows);
  fclose(f);
  return 0;
}
