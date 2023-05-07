#ifndef STNC_H
#define STNC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <mbedtls/md5.h>

#define MAX_MESSAGE_LEN 1024
#define BACKLOG 5
#define CHUNK_SIZE 104857600 // 100MB

void error(const char *msg);
unsigned char *generate_data();
void generate_checksum(unsigned char *data, unsigned char *checksum);
void transmit_data(int sockfd, unsigned char *data, int size);
void transmit_data_mmap(int sockfd, const char *filename);
void transmit_data_pipe(int sockfd, const char *filename);
void transmit_data_uds(int sockfd, const char *filename, int is_datagram);
void perform_test(int sockfd, const char *param);

#endif
