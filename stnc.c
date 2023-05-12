#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <openssl/sha.h>

enum addr
{
    IPV4,
    IPV6
};
#define DATA_SIZE 100000000
#define BUF_SIZE 64000
#define TCP_BUF_SIZE 1000000

void printUsage();
void handleClient(int argc, char *argv[]);
void handleServer(int argc, char *argv[]);
int init_client(int argc, char *argv[]);
int udp_client(int argc, char *argv[], enum addr type);

int main(int argc, char *argv[])
{
    if (argc < 3 || argc > 7 || (argc == 5 && !strcmp(argv[1], "-c")) || (argc == 6 && !strcmp(argv[1], "-c")))
    {
        fprintf(stderr, "Incorrect number of arguments\n");
        printUsage();
        return -1;
    }

    if (!strcmp(argv[1], "-c"))
    {
        handleClient(argc, argv);
    }
    else if (!strcmp(argv[1], "-s"))
    {
        handleServer(argc, argv);
    }
    else
    {
        fprintf(stderr, "Incorrect number of arguments\n");
        printUsage();
    }

    return 0;
}

void printUsage()
{
    printf("Server Usage: ./stnc -s <Port> <Check Flag> <Quiet Flag>\n"
           "Check Flag (not obligatory): -p (test communication)\n"
           "Quiet Flag (with check flag): -q (only testing results will be printed)\n\n"
           "Client Usage: ./stnc -c <IP> <Port> <Check Flag> <Type> <Param>\n"
           "Check Flag (not obligatory): -p\n"
           "Type (with check flag): ipv4/ipv6 | uds | mmap/pipe\n"
           "Param (with type): udp/tcp | dgram/stream | filename\n");
}

void handleClient(int argc, char *argv[])
{
    if (argv[4] == NULL)
    {
        init_client(argc, argv);
    }
    else if (!strcmp(argv[4], "-p"))
    {
        if (!strcmp(argv[5], "ipv4"))
        {
            if (!strcmp(argv[6], "tcp"))
            {
                tcp_client(argc, argv);
            }
            else if (!strcmp(argv[6], "udp"))
            {
                init_udp_client(argc, argv);
            }
        }
        else if (!strcmp(argv[5], "ipv6"))
        {
            if (!strcmp(argv[6], "tcp"))
            {
                tcp_client(argc, argv);
            }
            else if (!strcmp(argv[6], "udp"))
            {
                init_udp_client(argc, argv);
            }
        }
        else if (!strcmp(argv[5], "uds"))
        {
            if (!strcmp(argv[6], "stream"))
            {
                uds_stream_client(argc, argv);
            }
            else if (!strcmp(argv[6], "dgram"))
            {
                uds_dgram_client(argc, argv);
            }
        }
        else if (!strcmp(argv[5], "mmap"))
        {
            mmap_client(argc, argv);
        }
        else if (!strcmp(argv[5], "pipe"))
        {
            pipe_client(argc, argv);
        }
    }
}

void handleServer(int argc, char *argv[])
{
    if (argv[3] != NULL)
    {
        char *serverType = getServerType(argc, argv);
        if (strcmp(serverType, "tcp4") == 0)
        {
            tcp_server(argc, argv);
        }
        else if (strcmp(serverType, "tcp6") == 0)
        {
            tcp_server(argc, argv);
        }
        else if (strcmp(serverType, "udp4") == 0)
        {
            udp_server(argc, argv);
        }
        else if (strcmp(serverType, "udp6") == 0)
        {
            udp_server(argc, argv);
        }
        else if (strcmp(serverType, "udss") == 0)
        {
            uds_stream_server(argc, argv);
        }
        else if (strcmp(serverType, "udsd") == 0)
        {
            uds_dgram_server(argc, argv);
        }
        else if (strcmp(serverType, "mmap") == 0)
        {
            mmap_server(argc, argv);
        }
        else if (strcmp(serverType, "pipe") == 0)
        {
            pipe_server(argc, argv);
        }
        free(serverType);
    }
    else
    {
        server(argc, argv);
    }
}

int init_client(int argc, char *argv[])
{
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1)
    {
        perror("--Error--socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr =
        {
            .sin_family = AF_INET,
            .sin_port = htons(atoi(argv[3])),
        };
    if (inet_pton(AF_INET, argv[2], &serv_addr.sin_addr) <= 0)
    {
        perror("--Error--address invalid or not supported");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (connect(socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        perror("--Error--connection failed");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server Connection Established!\n");

    fd_set readfds;
    char message[BUF_SIZE];

    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(socket_fd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);

        struct timeval timeout =
            {
                .tv_sec = 10,
                .tv_usec = 0,
            };

        int maxfd = (socket_fd > STDIN_FILENO) ? socket_fd : STDIN_FILENO;
        int res = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
        if (res == -1)
        {
            perror("--Error--in select");
            exit(EXIT_FAILURE);
        }
        else if (res == 0)
        {
            continue;
        }
        else
        {
            if (FD_ISSET(STDIN_FILENO, &readfds))
            {
                if (fgets(message, BUF_SIZE, stdin) == NULL)
                {
                    perror("--Error--reading input");
                    exit(EXIT_FAILURE);
                }

                int bytes = send(socket_fd, message, strlen(message), 0);
                if (bytes == -1)
                {
                    perror("--Error--sending message");
                    exit(EXIT_FAILURE);
                }
            }

            if (FD_ISSET(socket_fd, &readfds))
            {
                int bytes = recv(socket_fd, message, BUF_SIZE, 0);
                if (bytes == -1)
                {
                    perror("--Error--receiving message");
                    exit(EXIT_FAILURE);
                }
                else if (bytes == 0)
                {
                    printf("server closed the connection\n");
                    break;
                }
                else
                {
                    message[bytes] = '\0';
                    printf("Server msg: %s", message);
                }
            }
        }
    }

    close(socket_fd);
    return 0;
}

// function to run udp client communication
/**
 * Initializes a UDP client and sends data to a server.
 *
 * @param argc  The number of command line arguments.
 * @param argv  The command line arguments.
 * @param type  The address type (IPV4 or IPV6).
 * @return      0 on success, -1 on error.
 */
int init_udp_client(int argc, char *argv[], enum addr type)
{
    char *serverType = (type == IPV4) ? "udp4" : "udp6";
    send_type_to_server(argc, argv, serverType);

    int sock = 0;
    int sendStream = 0, totalSent = 0;
    struct sockaddr_in servAddress4;
    struct sockaddr_in6 servAddress6;
    char buffer[BUF_SIZE] = {0};
    struct timeval startTime, endTime;
    const char *endMsg = "END";

    // Create socket
    if (type == IPV4)
    {
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
        {
            printf("\nSocket creation error\n");
            return -1;
        }

        memset(&servAddress4, 0, sizeof(servAddress4));

        // Set socket address
        servAddress4.sin_family = AF_INET;
        servAddress4.sin_port = htons(atoi(argv[3]));

        // Convert IPv4 and store in sin_addr
        if (inet_pton(AF_INET, argv[2], &servAddress4.sin_addr) <= 0)
        {
            printf("\nInvalid address/Address not supported\n");
            return -1;
        }
    }
    else if (type == IPV6)
    {
        sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sock < 0)
        {
            printf("\nSocket creation error\n");
            return -1;
        }

        memset(&servAddress6, 0, sizeof(servAddress6));

        // Set socket address
        servAddress6.sin6_family = AF_INET6;
        servAddress6.sin6_port = htons(atoi(argv[3]));

        // Convert IPv4 and store in sin_addr
        if (inet_pton(AF_INET6, argv[2], &servAddress6.sin6_addr) <= 0)
        {
            printf("\nInvalid address/Address not supported\n");
            return -1;
        }
    }
    else
    {
        printf("Invalid address type\n");
        return -1;
    }

    // Generate data
    char *data = generate_rand_str(DATA_SIZE);

    // Calculate and send checksum
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)data, strlen(data), hash);
    char hashStr[SHA_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        sprintf(&hashStr[i * 2], "%02x", hash[i]);
    }
    hashStr[SHA_DIGEST_LENGTH * 2] = '\0';

    // Send checksum
    if (type == IPV4)
    {
        sendStream = sendto(sock, hashStr, strlen(hashStr), 0, (struct sockaddr *)&servAddress4, sizeof(servAddress4));
    }
    else if (type == IPV6)
    {
        sendStream = sendto(sock, hashStr, strlen(hashStr), 0, (struct sockaddr *)&servAddress6, sizeof(servAddress6));
    }
    if (-1 == sendStream)
    {
        printf("send() failed");
        exit(1);
    }

    gettimeofday(&startTime, 0);
    int i = 0;
    while (totalSent < strlen(data))
    {
        int bytesToSend = (BUF_SIZE < strlen(data) - totalSent) ? BUF_SIZE : (int)(strlen(data) - totalSent);
        memcpy(buffer, data + totalSent, bytesToSend);
        if (type == IPV4)
        {
            sendStream = sendto(sock, buffer, bytesToSend, 0, (struct sockaddr *)&servAddress4, sizeof(servAddress4));
        }
        else if (type == IPV6)
        {
            sendStream = sendto(sock, buffer, bytesToSend, 0, (struct sockaddr *)&servAddress6, sizeof(servAddress6));
        }
        if (-1 == sendStream)
        {
            printf("send() failed");
            exit(1);
        }

        totalSent += sendStream;
        if (i % 200 == 0 || bytesToSend < BUF_SIZE)
        {
            printf("Total bytes sent: %d\n", totalSent);
        }

        sendStream = 0;
        i++;
        memset(buffer, 0, sizeof(buffer));
    }

    gettimeofday(&endTime, 0);
    strcpy(buffer, endMsg);
    if (type == IPV4)
    {
        sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr *)&servAddress4, sizeof(servAddress4));
    }
    else if (type == IPV6)
    {
        sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr *)&servAddress6, sizeof(servAddress6));
    }

    unsigned long milliseconds = (endTime.tv_sec - startTime.tv_sec) * 1000 + (endTime.tv_usec - startTime.tv_usec) / 1000;
    printf("Time elapsed: %lu milliseconds\n", milliseconds);

    // Close socket
    close(sock);
    free(data);
    return 0;
}