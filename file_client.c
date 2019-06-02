#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  // Parameter parsing
  if (argc != 4) {
    fprintf(stderr, "Usage: %s HOSTNAME PORT FILENAME\n", argv[0]);
    exit(1);
  }

  // Check port number
  // 16 bit unsigned integer (1 to 2^16)
  if (atoi(argv[2]) < 1 || atoi(argv[2]) > (1 << 16)) {
    fprintf(stderr, "Invalid port number: %d\n", atoi(argv[2]));
    exit(1);
  }

  // Get the address

  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo)); // Zero out the hints structure

  hints.ai_family = AF_INET; // IPv4
  hints.ai_socktype = SOCK_STREAM; // TCP
  hints.ai_flags = 0; // No flags
  hints.ai_protocol = 0; // Automatic protocol selection

  struct addrinfo *result; // Structure to store the result in

  // DNS query
  if (getaddrinfo(argv[1], argv[2], &hints, &result) == -1) {
    perror("Could not find address");
    exit(1);
  }

  int sock;
  struct addrinfo* rp;
  /*
    getaddrinfo returns a linked list of possible addresses
    Try each address and return if successful
  */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    // Create a socket on the found address
    if ((sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) {
      continue;
    }
    // Check if a connection is possible
    if (connect(sock, rp->ai_addr, rp->ai_addrlen) == -1) {
      close(sock); // The connection failed, close the socket
    } else {
      break; // The connection was successful
    }
  }
  if (rp == NULL) {
    // If we tried all addresses and none connected, fail
    fprintf(stderr, "No address was found\n");
    exit(1);
  }

  // Send a payload
  int file;
  if ((file = open(argv[3], O_RDONLY)) == -1) {
    perror("Could not open file");
    exit(1);
  }

  // Send file
  char buf[1024];
  int read_bytes;
  while ((read_bytes = read(file, buf, 1024)) > 0) {
    int wrote_bytes;
    wrote_bytes = write(sock, buf, read_bytes);
    printf("Wrote %d bytes\n", wrote_bytes);
  }

  close(file);
  close(sock);
}