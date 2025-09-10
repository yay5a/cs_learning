#include "agg/agg.h"
#include "datalink/datalink.h"
#include "emit/emit.h"
#include "l4/l4.h"
#include "net/net.h"
#include "pcap_io/pcap_io.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  agg_t *agg;
  net_limits_t net_limits;
} ctx_t;

static int handle_packet(const struct pcap_pkthdr *hdr, const uint8_t *data,
                         void *user) {
  ctx_t *ctx = (ctx_t *)user;
  eth_frame_t eth;
  const uint8_t *payload;
  size_t payload_len;
  if (datalink_parse_ethernet(data, hdr->caplen, &eth, &payload,
                              &payload_len) != 0) {
    return 0;
  }
  agg_add_mac(ctx->agg, eth.src);
  agg_add_mac(ctx->agg, eth.dst);
  net_packet_t npkt;
  if (net_parse(eth.ethertype, payload, payload_len, &ctx->net_limits, &npkt) !=
      0) {
    return 0;
  }
  l4_ports_t ports;
  if (l4_parse_ports(npkt.proto, npkt.payload, npkt.payload_len, &ports) != 0) {
    ports.src = ports.dst = 0;
  }
  flow_key_t key;
  key.version = npkt.version;
  memcpy(key.src, npkt.src, 16);
  memcpy(key.dst, npkt.dst, 16);
  key.proto = npkt.proto;
  key.sport = ports.src;
  key.dport = ports.dst;
  agg_add_flow(ctx->agg, &key);
  return 0;
}

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s --file <pcap> [--max-pkts N] [--max-bytes N] [--max-flows "
          "N] [--max-macs N] [--max-exthdrs N]\n",
          prog);
}

int main(int argc, char **argv) {
  struct options {
    const char *file;
    uint64_t max_pkts;
    uint64_t max_bytes;
    size_t max_flows;
    size_t max_macs;
    uint8_t max_exthdrs;
  } opts;
  memset(&opts, 0, sizeof(opts));
  opts.max_flows = 10000;
  opts.max_macs = 1000;
  opts.max_exthdrs = 8;
  static struct option long_opts[] = {
      {"file", required_argument, 0, 'f'},
      {"max-pkts", required_argument, 0, 'p'},
      {"max-bytes", required_argument, 0, 'b'},
      {"max-flows", required_argument, 0, 'F'},
      {"max-macs", required_argument, 0, 'M'},
      {"max-exthdrs", required_argument, 0, 'E'},
      {0, 0, 0, 0}};
  int opt;
  while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'f':
      opts.file = optarg;
      break;
    case 'p':
      opts.max_pkts = strtoull(optarg, NULL, 10);
      break;
    case 'b':
      opts.max_bytes = strtoull(optarg, NULL, 10);
      break;
    case 'F':
      opts.max_flows = strtoull(optarg, NULL, 10);
      break;
    case 'M':
      opts.max_macs = strtoull(optarg, NULL, 10);
      break;
    case 'E':
      opts.max_exthdrs = (uint8_t)strtoul(optarg, NULL, 10);
      break;
    default:
      usage(argv[0]);
      return 1;
    }
  }
  if (!opts.file) {
    usage(argv[0]);
    return 1;
  }
  agg_t agg;
  agg_init(&agg, opts.max_macs, opts.max_flows);
  ctx_t ctx;
  ctx.agg = &agg;
  ctx.net_limits.max_exthdrs = opts.max_exthdrs;
  pcap_limits_t limits;
  limits.max_pkts = opts.max_pkts;
  limits.max_bytes = opts.max_bytes;
  pcap_stats_t stats;
  if (pcap_io_run(opts.file, &limits, handle_packet, &ctx, &stats) != 0) {
    fprintf(stderr, "Failed to process pcap\n");
    agg_free(&agg);
    return 1;
  }
  emit_text(&agg);
  agg_free(&agg);
  return 0;
}
