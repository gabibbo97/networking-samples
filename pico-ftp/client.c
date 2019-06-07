#include <stdio.h>
#include <stdlib.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>

#include <libgen.h>
#include <sys/stat.h>

void socketskip(int fd, int count) {
  char buf;
  for (int i = 0; i < count; i++)
    recv(fd, &buf, 1, MSG_WAITALL);
}

void _socket_newline(int fd, int skip) {
  char resp;
  for (;;) {
    recv(fd, &resp, 1, 0);
    if (resp == '\n')
      break;
    if (skip)
      continue;
    printf("%c", resp);
  }
  printf("\n");
}

void skip_until_newline(int fd) { _socket_newline(fd, 1); }

void echo_until_newline(int fd) { _socket_newline(fd, 0); }

char receiveone(int fd) {
  char rec;
  recv(fd, &rec, 1, MSG_WAITALL);
  return rec;
}

int main(int argc, char *argv[]) {
  if (argc < 4) {
    fprintf(stderr, "USAGE: %s SERVER PORT <command>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  // Check port number
  if (atoi(argv[2]) < 1 || atoi(argv[2]) > (1 << 16)) {
    fprintf(stderr, "Invalid port number %d\n", atoi(argv[2]));
    exit(EXIT_FAILURE);
  }

  // Get server address and open a socket to it
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo)); // Zero out the hints structure

  hints.ai_family = AF_INET;       // IPv4
  hints.ai_socktype = SOCK_STREAM; // TCP
  hints.ai_flags = 0;              // No flags
  hints.ai_protocol = 0;           // Automatic protocol selection

  struct addrinfo *result; // Structure to store the result in

  // DNS query
  if (getaddrinfo(argv[1], argv[2], &hints, &result) == -1) {
    perror("Could not find address");
    exit(1);
  }

  int sock = -1;
  struct addrinfo *rp;
  /*
    getaddrinfo returns a linked list of possible addresses
    Try each address and return if successful
  */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    // Create a socket on the found address
    if ((sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) ==
        -1) {
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
    exit(EXIT_FAILURE);
  }

  // Authenticate
  for (;;) {
    dprintf(sock, "LOGGED\n");

    // Receive an AUTH OK
    char recvbuf[8];
    recv(sock, &recvbuf, 8, MSG_WAITALL);

    if (memcmp(&recvbuf, "AUTH OK\n", 8) == 0) {
      socketskip(sock, 1);
      printf("Authentication successful\n");
      break;
    }

    // Received an AUTH ERR
    socketskip(sock, 1);

    if (getenv("USERNAME") == NULL || getenv("PASSWORD") == NULL) {
      printf("Authorization required\n");
      printf("Username: ");
      char *username;
      scanf("%ms", &username);

      printf("Password: ");
      char *password;
      scanf("%ms", &password);

      dprintf(sock, "AUTH %s %s\n", username, password);

      free(username);
      free(password);
    } else {
      dprintf(sock, "AUTH %s %s\n", getenv("USERNAME"), getenv("PASSWORD"));
    }

    char is_error[3];
    recv(sock, &is_error, 3, MSG_WAITALL);
    if (memcmp(is_error, "ERR", 3) == 0) {
      printf("ERROR");
      echo_until_newline(sock);
      exit(EXIT_FAILURE);
    } else {
      skip_until_newline(sock);
      break;
    }
  }

  // Handle commands
  int command_ok = 0;

  if (strlen(argv[3]) == 2 && strncmp(argv[3], "ls", 2) == 0) {
    dprintf(sock, "LS\n");

    // File count
    socketskip(sock, 11); // Read "FILES COUNT "

    char file_size_buf[256];
    memset(&file_size_buf, '\0', 256);
    char charbuf;

    for (int file_size_length = 0;; file_size_length++) {
      recv(sock, &charbuf, 1, 0);
      if (charbuf == '\n') {
        break;
      }
      file_size_buf[file_size_length] = charbuf;
    }

    int direntries = atoi(file_size_buf);

    // Directory listing
    if (direntries > 0) {

      char recvb;
      int received_entries = 0;
      for (;;) {
        unsigned int recv_len = recv(sock, &recvb, 1, MSG_WAITALL);
        printf("%c", recvb);
        if (recvb == '\n') {
          received_entries++;
          if (received_entries == direntries)
            break;
        }
        if (recv_len < 1) {
          break;
        }
      }

    } else {
      // No file is present
      printf("Directory empty\n");
    }

    command_ok = 1;
  }

  if (strlen(argv[3]) == 6 && strncmp(argv[3], "upload", 6) == 0) {
    if (argc < 5) {
      fprintf(stderr, "USAGE: %s SERVER PORT upload FILENAME\n", argv[0]);
      exit(EXIT_FAILURE);
    }
    // Get file data
    struct stat file_info;
    if (stat(argv[4], &file_info) == -1) {
      perror("Could not stat file");
      exit(EXIT_FAILURE);
    }
    // Open file
    FILE *file_to_upload = fopen(argv[4], "r");
    if (file_to_upload == NULL) {
      perror("Could not open file");
      exit(EXIT_FAILURE);
    }
    // Upload file
    dprintf(sock, "UPLOAD %s SIZE %ld\n", basename(argv[4]), file_info.st_size);
    while (!feof(file_to_upload)) {
      char buf[128];
      unsigned int read_bytes = fread(&buf, sizeof(char), 128, file_to_upload);
      send(sock, &buf, read_bytes, 0);
    }
    dprintf(sock, "\n");
    // Get result
    echo_until_newline(sock);
    // Cleanup
    fclose(file_to_upload);
    command_ok = 1;
  }

  if (strlen(argv[3]) == 8 && strncmp(argv[3], "download", 8) == 0) {
    if (argc < 5) {
      fprintf(stderr, "USAGE: %s SERVER PORT download FILENAME\n", argv[0]);
      exit(EXIT_FAILURE);
    }
    // Perform request
    dprintf(sock, "DOWNLOAD %s\n", basename(argv[4]));
    // Check for error
    char errbuf[3];
    recv(sock, &errbuf, 3, MSG_WAITALL);
    if (memcmp(&errbuf, "ERR", 3) == 0) {
      fprintf(stderr, "ERROR");
      echo_until_newline(sock);
      exit(EXIT_FAILURE);
    }
    // Consume until "E SIZE "
    socketskip(sock, 7);
    // Get file size
    char file_size_buf[256];
    memset(&file_size_buf, '\0', 256);
    char charbuf;

    for (int file_size_length = 0;; file_size_length++) {
      recv(sock, &charbuf, 1, 0);
      if (charbuf == '\n') {
        break;
      }
      file_size_buf[file_size_length] = charbuf;
    }
    unsigned int file_size = atoi(file_size_buf);
    // Copy file
    FILE *file = fopen(basename(argv[4]), "w");
    if (file == NULL) {
      perror("Could not open file");
      exit(EXIT_FAILURE);
    }
    while (file_size > 0) {
      int buf_size = 128;
      if (buf_size > (int)file_size) {
        buf_size = file_size;
      }
      char buf[buf_size];
      ssize_t received_bytes = recv(sock, &buf, buf_size, MSG_WAITALL);
      fwrite(&buf, sizeof(char), received_bytes, file);
      file_size -= received_bytes;
      printf("Received %ld bytes, remaining %d bytes\n", received_bytes,
             file_size);
    }
    fclose(file);
    command_ok = 1;
  }

  if (!command_ok) {
    fprintf(stderr, "Unknown command\n");
    exit(EXIT_FAILURE);
  } else {
    dprintf(sock, "EXIT\n");
  }

  // Close socket
  freeaddrinfo(result);
  if (sock != -1)
    shutdown(sock, SHUT_RDWR);
}