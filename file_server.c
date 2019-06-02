#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


int sock;

// Close the socket
void close_socket(int signum) {
  close(sock);
  exit(0);
}

int main(int argc, char* argv[]) {
  // Parameter parsing
  if (argc != 2) {
    fprintf(stderr, "Usage: %s PORT\n", argv[0]);
    exit(1);
  }
  // Open socket
  /*
    AF_INET     => IPv4
    SOCK_STREAM => Reliable two-way transmission
    0           => Choose automatically a suitable protocol (TCP in this case)
  */
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("Could not create socket");
    exit(1);
  }
  // On interruption close the socket file descriptor
  signal(SIGINT, close_socket);
  signal(SIGHUP, close_socket);
  // Check port number
  // 16 bit unsigned integer (1 to 2^16)
  if (atoi(argv[1]) < 1 || atoi(argv[1]) > (1 << 16)) {
    fprintf(stderr, "Invalid port number: %d\n", atoi(argv[1]));
    exit(1);
  }

  // Create address
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(struct sockaddr_in));

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(atoi(argv[1]));
  server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on any address

  // Bind socket to an address
  if (bind(sock, (struct sockaddr*) &server_addr, sizeof(struct sockaddr_in)) == -1) {
    perror("Could not bind");
    exit(1);
  }

  // Listen on the socket
  // Maximum of 5 connections
  if (listen(sock, 5) == -1) {
    perror("Could not listen");
    exit(1);
  }

  // Accept connections
  int received_files_count = 1;
  while (1) {
    // This struct is used to get the client address
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));

    // Listen for the connection
    int client_fd;
    socklen_t client_addr_size = sizeof(client_addr);
    if ((client_fd = accept(sock, (struct sockaddr*) &client_addr, &client_addr_size)) == -1) {
      perror("Error in connection");
      continue;
    }

    // Print the received data
    int read_bytes_count;
    char buf[1024];
    memset(buf, '\0', 1024); // Avoid leaking information

    char filename[128];
    snprintf(filename, 128, "received-%d", received_files_count);
    int local_file;

    if ((local_file = open(filename, O_CREAT|O_TRUNC|O_WRONLY)) == -1) {
      close(client_fd);
      close(sock);
      perror("Could not open receive file");
      exit(1);
    }

    while ((read_bytes_count = recv(client_fd, buf, 1024, 0)) > 0) {
      printf("Received %d bytes\n", read_bytes_count);

      if (write(local_file, buf, read_bytes_count) < read_bytes_count) {
        fprintf(stderr,"Wrote less than expected\n");
      }

      memset(buf, '\0', 1024); // Reset the buffer
    }
    close(local_file);
    close(client_fd);

    printf("Received file %s\n", filename);

    received_files_count++;
  }
  close(sock);
}