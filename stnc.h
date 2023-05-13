#ifndef STNC_H
#define STNC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define TCP_BUF_SIZE 1024
#define UDP_BUF_SIZE 1024
#define UNIX_BUF_SIZE 1024
#define DATA_SIZE 1024
#define UDS_PATH "stnc_socket"

enum addr
{
    IPV4,
    IPV6
};

int server(int argc, char *argv[]);
int tcp_client(int argc, char *argv[], enum addr type);
int tcp_server(int argc, char *argv[], enum addr type);
int init_udp_client(int argc, char *argv[], enum addr type);
int init_udp_server(int argc, char *argv[], enum addr type);
int uds_stream_client(int argc, char *argv[]);
int uds_stream_server(int argc, char *argv[]);
int uds_dgram_client(int argc, char *argv[]);
int uds_dgram_server(int argc, char *argv[]);
int mmap_client(int argc, char *argv[]);
int mmap_server(int argc, char *argv[]);
int pipe_client(int argc, char *argv[]);
int pipe_server(int argc, char *argv[]);
void printUsage();
void handleClient(int argc, char *argv[]);
void handleServer(int argc, char *argv[]);
int init_client(int argc, char *argv[]);
void send_checksum(char *data, int sock);
char *generate_data(size_t size);
int receive_checksum(int serverSocket, enum addr type, unsigned char *recv_hash);
int bind_udp_server_socket(int serverSocket, enum addr type, const char *port);
int create_udp_server_socket(int argc, char *argv[], enum addr type);

// Aid functions
char *getServerType(int argc, char *argv[]);
int send_type_to_server(int argc, char *argv[], char *type);
char *generate_rand_str(int length);
int min(int a, int b);

#endif /* STNC_H */
