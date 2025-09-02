#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

struct file_header {
  uint32_t magic_number;  // pcap format
  uint16_t version_major; // Major version
  uint16_t version_minor; // Minor version
  int32_t thiszone;       // Timezone offset
  uint32_t sigfigs;       // Timestamp accuracy
  uint32_t snaplen;       // Max captured packet size
  uint32_t network;       // Link layer type
};

struct pkt_header {
  uint32_t ts_seconds;  // UNIX timestamps
  uint32_t ts_useconds; // Microseconds
  uint32_t caplen;      // Capture length
  uint32_t oglen;       // Original length
};

struct ethernet_header {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t ethtype;
};

struct ip_header {
  uint8_t ip_verlen;
  uint8_t service_type;
  uint16_t pkt_len;
  uint16_t pkt_id;
  uint16_t flags_fragment;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t chksum;
  uint32_t srcip;
  uint32_t dstip;
};

struct udp_header {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t chksum;
};

struct tcp_header {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint8_t header_len;
  uint16_t urg_pointer;
  uint32_t tcp_opts;
};

int main(int argc, char *argv[]) {

  // Open file and read through binary...
  FILE *file = fopen("pcap_2025-09-01_08-36-18.pcap", "rb");
  if (file == NULL) {
    printf("Error opening file\n");
    return 1;
  }
  // Read through file header
  struct file_header fheader;
  size_t fheader_bytes_read = fread(&fheader, sizeof(fheader), 1, file);
  if (fheader_bytes_read == 0) {
    printf("Error reading file header\n");
    fclose(file);
    return 1;
  }

  // Print file header data
  printf("Magic number: 0x%x\n", fheader.magic_number);
  printf("Major version: 0x%x\n", fheader.version_major);
  printf("Minor version: 0x%x\n", fheader.version_minor);
  printf("Snapshot length: 0x%x\n", fheader.snaplen);
  printf("Network: 0x%x\n", fheader.network);
  printf("Time zone: 0x%x\n", fheader.thiszone); // fix
  printf("Timestamp: 0x%x\n", fheader.sigfigs);  // fix

  // Read packet header
  struct pkt_header pkt_header;
  size_t pkt_head_bytes_read = fread(&pkt_header, sizeof(pkt_header), 1, file);
  if (pkt_head_bytes_read == 0) {
    printf("Error reading packet header\n");
    fclose(file);
    return 1;
  }
  // Print packet header data
  printf("Timestamp: 0x%x\n", pkt_header.ts_seconds);
  printf("Microseconds: 0x%x\n", pkt_header.ts_useconds);
  printf("Capture length: 0x%x\n", pkt_header.caplen);
  printf("Original length: 0x%x\n", pkt_header.oglen);

  // Read ethernet_header
  struct ethernet_header ethnheader;
  size_t eth_header_bytes_read =
      fread(&ethnheader, sizeof(ethnheader), 1, file);
  if (eth_header_bytes_read == 0) {
    printf("Error reading ethernet header");
    fclose(file);
    return 1;
  }

  // Print ethernet header data
  printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         ethnheader.dst_mac[0], ethnheader.dst_mac[1], ethnheader.dst_mac[2],
         ethnheader.dst_mac[3], ethnheader.dst_mac[4], ethnheader.dst_mac[5]);

  printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethnheader.src_mac[0],
         ethnheader.src_mac[1], ethnheader.src_mac[2], ethnheader.src_mac[3],
         ethnheader.src_mac[4], ethnheader.src_mac[5]);

  printf("Ethernet type: 0x%04x\n", ntohs(ethnheader.ethtype));

  // Read IP header
  struct ip_header ip_header;
  size_t ip_head_bytes_read = fread(&ip_header, sizeof(ip_header), 1, file);
  if (ip_head_bytes_read == 0) {
    printf("Error reading IPs\n");
    fclose(file);
    return 1;
  }

  // Print IP header data
  printf("IP version & length: 0x%x\n", ip_header.ip_verlen);
  printf("Service type: 0x%x\n", ip_header.service_type);
  printf("Total length: 0x%x\n", ip_header.pkt_len);
  printf("Time to live: 0x%x\n", ip_header.ttl);
  printf("Protocol: 0x%x\n", ip_header.protocol);
  printf("Checksum: 0x%x\n", ip_header.chksum);
  printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header.srcip));
  printf("Destination IP: %s\n",
         inet_ntoa(*(struct in_addr *)&ip_header.dstip));

  // Switch header read based on protocol
  switch (ip_header.protocol) {
  case 0x01:
    printf("ICMP\n");
    // Read and print ICMP header
    break;
  case 0x06:
    printf("TCP\n");
    // Read TCP header
    struct tcp_header tcp_header;
    size_t tcp_head_bytes_read =
        fread(&tcp_header, sizeof(tcp_header), 1, file);
    if (tcp_head_bytes_read == 0) {
      printf("Error reading TCP header\n");
      fclose(file);
      return 1;
    }

    // Print TCP header data
    printf("Source port: 0x%x\n ", ntohs(tcp_header.src_port));
    printf("Destination port: 0x%x\n", ntohs(tcp_header.dst_port));
    printf("Sequence number: 0x%x\n", tcp_header.seq_num);
    printf("Acknowledgement number: 0x%x\n", tcp_header.ack_num);
    printf("TCP Header length: 0x%x\n", tcp_header.header_len);
    printf("Urgent pointer: 0x%x\n", tcp_header.urg_pointer);
    printf("TCP options: 0x%x\n", tcp_header.tcp_opts);
    break;
  case 0x11:
    printf("UDP\n");
    // Read UDP header
    struct udp_header udp_header;
    size_t udp_head_bytes_read =
        fread(&udp_header, sizeof(udp_header), 1, file);
    if (udp_head_bytes_read == 0) {
      printf("Error reading UDP header\n");
      fclose(file);
      return 1;
    }

    // Print UDP header data
    printf("Source port: 0x%x\n ", ntohs(udp_header.src_port));
    printf("Destination port: 0x%x\n", ntohs(udp_header.dst_port));
    printf("UDP packet length: 0x%x\n", udp_header.length);
    printf("Checksum: 0x%x\n", udp_header.chksum);
    break;
  default:
    printf("Unexpected protocol: 0x%x\n", ntohs(ip_header.protocol));
    break;
  }

  fclose(file);
  return EXIT_SUCCESS;
}
