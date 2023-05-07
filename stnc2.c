#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <openssl/md5.h>
#include "stnc2.h"
#include <sys/un.h>

#define MAX_MESSAGE_LEN 1024
#define BACKLOG 5

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

void generate_data(char *data, size_t size)
{
    // Generate random data
    srand(time(NULL));
    for (size_t i = 0; i < size; ++i)
    {
        data[i] = rand() % 256;
    }
}

void calculate_checksum(const char *data, size_t size, unsigned char *checksum)
{
    // Calculate MD5 checksum
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, size);
    MD5_Final(checksum, &ctx);
}

void transmit_tcp(const char *ip, int port, const char *data, size_t size, long *time_elapsed)
{
    int sockfd;
    struct sockaddr_in serv_addr;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("Error opening socket");
    }

    // Set up server address structure
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &(serv_addr.sin_addr)) <= 0)
    {
        error("Invalid IP address");
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        error("Error connecting to the server");
    }

    // Transmit data
    clock_t start_time = clock();
    send(sockfd, data, size, 0);
    clock_t end_time = clock();

    // Calculate time elapsed
    *time_elapsed = (end_time - start_time) * 1000 / CLOCKS_PER_SEC;

    // Close the socket
    close(sockfd);
}

void transmit_udp(const char *ip, int port, const char *data, size_t size, long *time_elapsed)
{
    int sockfd;
    struct sockaddr_in serv_addr;

    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        error("Error opening socket");
    }

    // Set up server address structure
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &(serv_addr.sin_addr)) <= 0)
    {
        error("Invalid IP address");
    }

    // Transmit data
    clock_t start_time = clock();
    sendto(sockfd, data, size, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    clock_t end_time = clock();

    // Calculate time elapsed
    *time_elapsed = (end_time - start_time) * 1000 / CLOCKS_PER_SEC;

    // Close the socket
    close(sockfd);
}

void transmit_mmap(const char *filename, const char *data, size_t size, long *time_elapsed)
{
    int fd;
    struct stat st;
    char *mapped_data;

    // Open the file
    fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        error("Error opening file");
    }

    // Truncate the file to the required size
    if (ftruncate(fd, size) < 0)
    {
        error("Error truncating file");
    }

    // Map the file into memory
    mapped_data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped_data == MAP_FAILED)
    {
        error("Error mapping file");
    }

    // Copy the data to the mapped file
    memcpy(mapped_data, data, size);

    // Flush the changes to disk
    if (msync(mapped_data, size, MS_SYNC) < 0)
    {
        error("Error syncing file");
    }

    // Close the file
    close(fd);

    // Calculate time elapsed
    *time_elapsed = 0; // Since mmap is instantaneous, time_elapsed is 0
}

void transmit_pipe(const char *filename, const char *data, size_t size, long *time_elapsed)
{
    int fd;
    ssize_t bytes_written;

    // Create the named pipe (FIFO)
    if (mkfifo(filename, S_IRUSR | S_IWUSR) < 0)
    {
        error("Error creating named pipe");
    }

    // Open the named pipe for writing
    fd = open(filename, O_WRONLY);
    if (fd < 0)
    {
        error("Error opening named pipe for writing");
    }

    // Write the data to the named pipe
    clock_t start_time = clock();
    bytes_written = write(fd, data, size);
    clock_t end_time = clock();

    // Calculate time elapsed
    *time_elapsed = (end_time - start_time) * 1000 / CLOCKS_PER_SEC;

    // Close the named pipe
    close(fd);

    // Remove the named pipe
    if (unlink(filename) < 0)
    {
        error("Error removing named pipe");
    }
}

void transmit_uds_stream(const char *filename, const char *data, size_t size, long *time_elapsed)
{
    int sockfd;
    struct sockaddr_un serv_addr;

    // Create socket
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("Error opening socket");
    }

    // Set up server address structure
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, filename, sizeof(serv_addr.sun_path) - 1);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        error("Error connecting to the server");
    }

    // Transmit data
    clock_t start_time = clock();
    send(sockfd, data, size, 0);
    clock_t end_time = clock();

    // Calculate time elapsed
    *time_elapsed = (end_time - start_time) * 1000 / CLOCKS_PER_SEC;

    // Close the socket
    close(sockfd);
}

void transmit_uds_dgram(const char *filename, const char *data, size_t size, long *time_elapsed)
{
    int sockfd;
    struct sockaddr_un serv_addr;

    // Create socket
    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        error("Error opening socket");
    }

    // Set up server address structure
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, filename, sizeof(serv_addr.sun_path) - 1);

    // Transmit data
    clock_t start_time = clock();
    sendto(sockfd, data, size, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    clock_t end_time = clock();

    // Calculate time elapsed
    *time_elapsed = (end_time - start_time) * 1000 / CLOCKS_PER_SEC;

    // Close the socket
    close(sockfd);
}

void perform_performance_test(const char *ip, int port, const char *filename, const char *type, const char *param)
{
    char data[100 * 1024 * 1024]; // 100MB data
    unsigned char checksum[MD5_DIGEST_LENGTH];
    long time_elapsed;

    // Generate data
    generate_data(data, sizeof(data));

    // Calculate checksum
    calculate_checksum(data, sizeof(data), checksum);

    // Perform transmission based on the selected type and param
    if (strcmp(type, "ipv4") == 0)
    {
        if (strcmp(param, "tcp") == 0)
        {
            transmit_tcp(ip, port, data, sizeof(data), &time_elapsed);
        }
        else if (strcmp(param, "udp") == 0)
        {
            transmit_udp(ip, port, data, sizeof(data), &time_elapsed);
        }
    }
    else if (strcmp(type, "ipv6") == 0)
    {
        if (strcmp(param, "tcp") == 0)
        {
            // Implement IPv6 TCP transmission
        }
        else if (strcmp(param, "udp") == 0)
        {
            // Implement IPv6 UDP transmission
        }
    }
    else if (strcmp(type, "mmap") == 0)
    {
        transmit_mmap(filename, data, sizeof(data), &time_elapsed);
    }
    else if (strcmp(type, "pipe") == 0)
    {
        transmit_pipe(filename, data, sizeof(data), &time_elapsed);
    }
    else if (strcmp(type, "uds") == 0)
    {
        if (strcmp(param, "stream") == 0)
        {
            transmit_uds_stream(filename, data, sizeof(data), &time_elapsed);
        }
        else if (strcmp(param, "dgram") == 0)
        {
            transmit_uds_dgram(filename, data, sizeof(data), &time_elapsed);
        }
    }

    // Print the result
    printf("%s_%s,%ld\n", type, param, time_elapsed);
}

int main(int argc, char *argv[])
{
    int opt;
    int is_server = 0;
    int is_performance_test = 0;
    int is_quiet = 0;
    int port = 0;
    char ip[INET6_ADDRSTRLEN];
    char filename[MAX_MESSAGE_LEN];
    char type[MAX_MESSAGE_LEN];
    char param[MAX_MESSAGE_LEN];

    // Parse command line arguments

    while ((opt = getopt(argc, argv, "s:p:c:q")) != -1)
    {
        switch (opt)
        {
        case 's':
            is_server = 1;
            port = atoi(optarg);
            break;
        case 'p':
            is_performance_test = 1;
            break;
        case 'c':
            strncpy(ip, strtok(optarg, ":"), sizeof(ip));
            port = atoi(strtok(NULL, ":"));
            strncpy(type, strtok(NULL, " "), sizeof(type));
            strncpy(param, strtok(NULL, " "), sizeof(param));
            break;
        case 'q':
            is_quiet = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s -s port -p -q\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // Check if server mode
    if (is_server)
    {
        // Server mode
        if (is_performance_test)
        {
            // Perform performance test
            printf("Running performance test...\n");
            perform_performance_test(NULL, port, NULL, type, param);
        }
        else
        {
            // Not a valid command, print usage
            fprintf(stderr, "Usage: %s -s port -p -q\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        // Client mode
        if (is_performance_test)
        {
            // Perform performance test
            printf("Running performance test...\n");
            perform_performance_test(ip, port, filename, type, param);
        }
        else
        {
            // Not a valid command, print usage
            fprintf(stderr, "Usage: %s -c IP:PORT -p TYPE PARAM\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
