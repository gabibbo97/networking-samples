#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>

// Data definitions
typedef struct pcaprec_hdr_s {
  unsigned int ts_sec;   /* timestamp seconds */
  unsigned int ts_usec;  /* timestamp microseconds */
  unsigned int incl_len; /* number of octets of packet saved in file */
  unsigned int orig_len; /* actual length of packet */
} pcaprec_hdr_t;

typedef struct ethernet_frame_s {
  unsigned char d_mac[6];    /* Destination mac */
  unsigned char s_mac[6];    /* Source mac */
  unsigned int  ulp;         /* Upper layer protocol */
} ethernet_frame_t;

typedef struct ipv4_frame_s {
  unsigned char header_length; /* Header length in bytes */
  unsigned char dsf;           /* Differentiated services field */
  unsigned int length;         /* Total length of the packet */
  unsigned int identification; /* Packet name */
  unsigned char flags[2];      /* Flags */
  unsigned char ttl;           /* Time to live */
  unsigned char proto;         /* Protocol */
  unsigned int checksum;       /* Checksum */
  unsigned char s_addr[4];     /* Source address */
  unsigned char d_addr[4];     /* Destination address */
} ipv4_frame_t;

typedef struct udp_frame_s {
  unsigned int s_port; // Source port
  unsigned int d_port; // Destination port
  unsigned int length; // Length
  unsigned int checksum; // Checksum
} udp_frame_t;

typedef struct tcp_frame_s {
  unsigned int s_port; // Source port
  unsigned int d_port; // Destination port
  unsigned long int seq_number; // Sequence number
  unsigned long int ack_number; // ACK number
  unsigned char header_length; // Header length
  unsigned char flags[2]; // Flags
  unsigned int window_size; // Window size
  unsigned int checksum; // Checksum
  unsigned int urgent_pointer; // Urgent pointer
  unsigned int payload_size; // TCP Payload size
} tcp_frame_t;

// Parsers
pcaprec_hdr_t* parse_pcap_header(FILE* fd) {
  pcaprec_hdr_t* header = (pcaprec_hdr_t*) malloc(sizeof(pcaprec_hdr_t));

  fread(&header->ts_sec, sizeof(unsigned int), 1, fd);
  fread(&header->ts_usec, sizeof(unsigned int), 1, fd);
  fread(&header->incl_len, sizeof(unsigned int), 1, fd);
  fread(&header->orig_len, sizeof(unsigned int), 1, fd);

  // If EOF was reached, end parsing
  if (feof(fd)) return NULL;

  return header;
}

ethernet_frame_t* parse_ethernet_frame(FILE* fd) {
  ethernet_frame_t* header = (ethernet_frame_t*) malloc(sizeof(ethernet_frame_t));

  fread(&header->d_mac, sizeof(unsigned char), 6, fd);
  fread(&header->s_mac, sizeof(unsigned char), 6, fd);

  unsigned char ulp_bytes[2];

  fread(&ulp_bytes, sizeof(unsigned char), 2, fd);

  // Generate the ULP bytes
  header->ulp = (ulp_bytes[0] << 8) + ulp_bytes[1];;

  return header;
}

ipv4_frame_t* parse_ipv4_frame(FILE* fd) {
  ipv4_frame_t* header = (ipv4_frame_t*) malloc(sizeof(ipv4_frame_t));
  // Check IPv4
  unsigned char protocol_version;
  fread(&protocol_version, sizeof(unsigned char), 1, fd);
  if ((protocol_version >> 4) != 4) {
    printf("Unexpected protocol version %d in IPv4 header!", protocol_version);
    exit(1);
  }
  header->header_length = (protocol_version & 15) << 2; // 1111 = 1 + 2 + 4 + 8 = 15
  // Parse fields
  fread(&header->dsf, sizeof(unsigned char), 1, fd);

  unsigned char len_bytes[2];
  fread(&len_bytes, sizeof(unsigned char), 2, fd);
  header->length = (len_bytes[0] << 8) + len_bytes[1];

  unsigned char id_bytes[2];
  fread(&id_bytes, sizeof(unsigned char), 2, fd);
  header->identification = (id_bytes[0] << 8) + id_bytes[1];

  fread(&header->flags, sizeof(unsigned char), 2, fd);
  fread(&header->ttl, sizeof(unsigned char), 1, fd);
  fread(&header->proto, sizeof(unsigned char), 1, fd);

  unsigned char chk_bytes[2];
  fread(&chk_bytes, sizeof(unsigned char), 2, fd);
  header->checksum = (chk_bytes[0] << 8) + chk_bytes[1];

  fread(&header->s_addr, sizeof(unsigned char), 4, fd);
  fread(&header->d_addr, sizeof(unsigned char), 4, fd);

  // Skip extra length if needed
  if (header->header_length > (5 << 2)) {
    unsigned int extra_len = header->header_length - (5 << 2);
    printf(" skipping %d bytes of extra IPv4 header \n", extra_len);
    fseek(fd, extra_len, SEEK_CUR);
  }

  return header;
}

tcp_frame_t* parse_tcp_frame(FILE* fd, unsigned int ipv4_payload_length) {
  tcp_frame_t* header = (tcp_frame_t*) malloc(sizeof(tcp_frame_t));

  unsigned char s_port_bytes[2];
  fread(&s_port_bytes, sizeof(unsigned char), 2, fd);
  header->s_port = (s_port_bytes[0] << 8) + s_port_bytes[1];

  unsigned char d_port_bytes[2];
  fread(&d_port_bytes, sizeof(unsigned char), 2, fd);
  header->d_port = (d_port_bytes[0] << 8) + d_port_bytes[1];

  unsigned char seq_num_bytes[4];
  fread(&seq_num_bytes, sizeof(unsigned char), 4, fd);
  header->seq_number = (seq_num_bytes[0] << 24) + (seq_num_bytes[1] << 16) + (seq_num_bytes[2] << 8) + seq_num_bytes[3];

  unsigned char ack_num_bytes[4];
  fread(&ack_num_bytes, sizeof(unsigned char), 4, fd);
  header->ack_number = (ack_num_bytes[0] << 24) + (ack_num_bytes[1] << 16) + (ack_num_bytes[2] << 8) + ack_num_bytes[3];

  fread(&header->flags, sizeof(unsigned char), 2, fd);
  header->header_length = (header->flags[0] >> 4) * 4;


  unsigned char win_size_bytes[2];
  fread(&win_size_bytes, sizeof(unsigned char), 2, fd);
  header->window_size = (win_size_bytes[0] << 8) + win_size_bytes[1];

  unsigned char chk_bytes[2];
  fread(&chk_bytes, sizeof(unsigned char), 2, fd);
  header->checksum = (chk_bytes[0] << 8) + chk_bytes[1];

  unsigned char urg_bytes[2];
  fread(&urg_bytes, sizeof(unsigned char), 2, fd);
  header->urgent_pointer = (urg_bytes[0] << 8) + urg_bytes[1];

  if (header->header_length > 20) {
    unsigned int extra_len = header->header_length - 20;
    printf(" skipping %d bytes of extra TCP header \n", extra_len);
    fseek(fd, extra_len, SEEK_CUR);
  }

  header->payload_size = ipv4_payload_length - header->header_length;

  fseek(fd, header->payload_size, SEEK_CUR);

  return header;
}

udp_frame_t* parse_udp_frame(FILE* fd) {
  udp_frame_t* header = (udp_frame_t*) malloc(sizeof(udp_frame_t));

  unsigned char s_port_bytes[2];
  fread(&s_port_bytes, sizeof(unsigned char), 2, fd);
  header->s_port = (s_port_bytes[0] << 8) + s_port_bytes[1];

  unsigned char d_port_bytes[2];
  fread(&d_port_bytes, sizeof(unsigned char), 2, fd);
  header->d_port = (d_port_bytes[0] << 8) + d_port_bytes[1];

  unsigned char len_bytes[2];
  fread(&len_bytes, sizeof(unsigned char), 2, fd);
  header->length = (len_bytes[0] << 8) + len_bytes[1];

  unsigned char chk_bytes[2];
  fread(&chk_bytes, sizeof(unsigned char), 2, fd);
  header->checksum = (chk_bytes[0] << 8) + chk_bytes[1];

  fseek(fd, header->length - 8, SEEK_CUR);

  return header;
}

// Formatting
void print_MAC(unsigned char mac[]) {
  for (int i = 0; i < 6; i++) {
    if (i != 0) {
      printf(":");
    }
    printf("%.2X", mac[i]);
  }
}

void print_ethernet_frame(ethernet_frame_t* ethernet_frame) {
  printf("ETHERNET => ");
  printf("DMAC: ");
  print_MAC(ethernet_frame->d_mac);

  printf(" SMAC: ");
  print_MAC(ethernet_frame->s_mac);

  printf(" ULP: %d ", ethernet_frame->ulp);

  if (ethernet_frame->ulp == 0x0800) {
    printf("(IPv4) ");
  } else {
    printf("(Unknown) ");
  }
  printf("\n");
}

void print_ipv4_frame(ipv4_frame_t* ipv4_frame) {
  printf("IPv4 => ");
  printf("Header length: %d ", ipv4_frame->header_length);
  printf("Total length: %d ", ipv4_frame->length);
  printf("Id: %d ", ipv4_frame->identification);
  printf("Protocol: ");
  switch (ipv4_frame->proto) {
    case 6:
      printf("TCP ");
      break;
    case 17:
      printf("UDP ");
      break;
    default:
      printf("Unknown ");
      break;
  }
  printf("TTL: %d ", ipv4_frame->ttl);
  printf("CHK: %X ", ipv4_frame->checksum);
  printf("SRC: %d.%d.%d.%d ", ipv4_frame->s_addr[0], ipv4_frame->s_addr[1], ipv4_frame->s_addr[2], ipv4_frame->s_addr[3]);
  printf("DST: %d.%d.%d.%d ", ipv4_frame->d_addr[0], ipv4_frame->d_addr[1], ipv4_frame->d_addr[2], ipv4_frame->d_addr[3]);
  printf("\n");
}

void print_tcp_frame(tcp_frame_t* tcp_frame) {
  printf("TCP => ");
  printf("Header length: %d ", tcp_frame->header_length);
  printf("SPORT: %d ", tcp_frame->s_port);
  printf("DPORT: %d ", tcp_frame->d_port);
  printf("SEQN: %ld ", tcp_frame->seq_number);
  printf("ACKN: %ld ", tcp_frame->ack_number);
  printf("Window size: %d ", tcp_frame->window_size);
  printf("Checksum: %d ", tcp_frame->checksum);
  printf("Payload size: %d ", tcp_frame->payload_size);

  if (tcp_frame->flags[1] & (1 << 4)) printf("ACK ");
  if (tcp_frame->flags[1] & (1 << 3)) printf("PSH ");
  if (tcp_frame->flags[1] & (1 << 2)) printf("RST ");
  if (tcp_frame->flags[1] & (1 << 1)) printf("SYN ");
  if (tcp_frame->flags[1] & (1 << 0)) printf("FIN ");

  printf("\n");
}

void print_udp_frame(udp_frame_t* udp_frame) {
  printf("UDP => ");
  printf("Header length: %d ", 8);
  printf("Total length: %d ", udp_frame->length);
  printf("SPORT: %d ", udp_frame->s_port);
  printf("DPORT: %d ", udp_frame->d_port);
  printf("Checksum: %d ", udp_frame->checksum);
  printf("\n");
}

// Dispatch
void dispatch_ipv4_protocol(FILE* fd, unsigned int payload_length, unsigned char protocol) {
  if (protocol == 6) {
    tcp_frame_t* tcp_frame = parse_tcp_frame(fd, payload_length);
    print_tcp_frame(tcp_frame);
    free(tcp_frame);
  } else if (protocol == 17) {
    udp_frame_t* udp_frame = parse_udp_frame(fd);
    print_udp_frame(udp_frame);
    free(udp_frame);
  } else {
    printf("Skipping %d bytes of unknown IPv4 payload\n", payload_length);
    fseek(fd, payload_length, SEEK_CUR);
  }
}

// Main
int main(int argc, char* argv[]) {
  // Argument parsing
  if (argc != 2) {
    fprintf(stderr, "USAGE: %s file\n", argv[0]);
    exit(1);
  }
  // File open
  FILE* pcap_file;
  if ((pcap_file = fopen(argv[1], "r")) == NULL) {
    perror("Could not open file");
    exit(1);
  }
  // Skip header (192 bits)
  fseek(pcap_file, 24, SEEK_SET);
  // Parse packets
  unsigned int packet_number = 1;
  unsigned int first_packet_timestamp;
  while (!feof(pcap_file)) {
    // Packet header
    pcaprec_hdr_t* packet_pcap_header = parse_pcap_header(pcap_file);

    // Skip broken headers
    if (packet_pcap_header == NULL) {
      continue;
    }

    if (packet_number == (unsigned int) 1) {
      first_packet_timestamp = packet_pcap_header->ts_sec;
    }
    unsigned int offset_from_first = packet_pcap_header->ts_sec - first_packet_timestamp;

    printf("=== Packet number: %d, time: %d, size: %d bytes ===\n", packet_number, offset_from_first, packet_pcap_header->orig_len);
    // Packet payload
    // Ethernet frame
    ethernet_frame_t* ethernet_frame = parse_ethernet_frame(pcap_file);
    print_ethernet_frame(ethernet_frame);
    if (ethernet_frame->ulp != 0x0800) {
      // Skip the rest of the payload if it is not an IPv4 packet
      fseek(pcap_file, packet_pcap_header->incl_len - sizeof(ethernet_frame_t), SEEK_CUR);
    }
    free(ethernet_frame);
    // IP Packet
    ipv4_frame_t* ipv4_frame = parse_ipv4_frame(pcap_file);
    print_ipv4_frame(ipv4_frame);
    dispatch_ipv4_protocol(pcap_file, ipv4_frame->length - ipv4_frame->header_length, ipv4_frame->proto);
    free(ipv4_frame);
    // Increment packet count
    printf("\n");
    packet_number++;
    // Cleanup
    free(packet_pcap_header);
  }
  // Close file descriptor
  fclose(pcap_file);
}