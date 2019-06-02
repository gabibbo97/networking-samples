#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


int main(int argc, char* argv[]) {
  // Parameter parsing
  if (argc != 3) {
    fprintf(stderr, "Usage: %s IP PORT\n", argv[0]);
    exit(1);
  }
  // Open socket
  /*
    AF_INET     => IPv4
    SOCK_STREAM => Reliable two-way transmission
    0           => Choose automatically a suitable protocol (TCP in this case)
  */
  int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("Could not create socket");
    exit(1);
  }
  // Create address
  struct sockaddr_in server_address;
  memset(&server_address, 0, sizeof(server_address)); // Zero-out all fields

  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(atoi(argv[2]));

  // Check port number
  // 16 bit unsigned integer (1 to 2^16)
  if (atoi(argv[2]) < 1 || atoi(argv[2]) > (1 << 16)) {
    fprintf(stderr, "Invalid port number: %d\n", atoi(argv[2]));
    exit(1);
  }

  // Parse address
  if (inet_pton(AF_INET, argv[1], &server_address.sin_addr) <= 0) {
    fprintf(stderr, "Could not parse the provided address\n");
    exit(1);
  }

  // Connect
  if (connect(sock, (struct sockaddr*) &server_address, sizeof(server_address)) == -1) {
    perror("Could not connect");
    exit(1);
  }

  // Send a payload every 100ms
  for (int i = 0; i < (1 << 7); i++) {
    char message[128];
    snprintf(message, 128, "Hello there, message number %d\n", i);
    if (send(sock, message, strnlen(message, 128), 0) == -1) {
      perror("Could not send");
      exit(1);
    }
    usleep(100 * 1000);
  }
  close(sock);
}