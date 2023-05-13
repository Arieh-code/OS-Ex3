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

#define SHM_FILE "/FileSM"
#define SHM_FILE_NAME "/FileName"
#define SHM_FILE_CS "/FileCS"
#define BUF_SIZE 64000
#define TCP_BUF_SIZE 1000000
#define FIFO_NAME "/tmp/myfifo"
#define DATA_SIZE 100000000
#define SOCKET_PATH "/tmp/my_socket.sock"
#define SERVER_SOCKET_PATH "/tmp/uds_dgram_server"
#define CLIENT_SOCKET_PATH "/tmp/uds_dgram_client"
enum addr
{
    IPV4,
    IPV6
};

// main functions
// int client(int argc, char *argv[]);
int server(int argc, char *argv[]);
int init_tcp_client(int argc, char *argv[], enum addr type);
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

// aid functions
char *getServerType(int argc, char *argv[]);
int send_type_to_server(int argc, char *argv[], char *type);
char *generate_rand_str(int length);
int min(int a, int b);

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

// ######################### udp server #########################

int create_udp_server_socket(int argc, char *argv[], enum addr type)
{
    struct sockaddr_in serverAddr, clientAddr;
    struct sockaddr_in6 serverAddr6, clientAddr6;
    socklen_t clientAddressLen;
    int serverSocket;

    if (type == IPV4)
    {
        // Create server socket
        if ((serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
            perror("Socket creation error");
            return -1;
        }

        memset(&serverAddr, 0, sizeof(serverAddr));
        memset(&clientAddr, 0, sizeof(clientAddr));

        // Set socket address
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(atoi(argv[2]));

        // Bind socket to address
        if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
        {
            perror("Bind failed");
            return -1;
        }
    }
    else if (type == IPV6)
    {
        // Create server socket
        if ((serverSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
            perror("Socket creation error");
            return -1;
        }

        memset(&serverAddr6, 0, sizeof(serverAddr6));
        memset(&clientAddr6, 0, sizeof(clientAddr6));

        // Set socket address
        serverAddr6.sin6_family = AF_INET6;
        serverAddr6.sin6_addr = in6addr_any;
        serverAddr6.sin6_port = htons(atoi(argv[2]));

        // Bind socket to address
        if (bind(serverSocket, (struct sockaddr *)&serverAddr6, sizeof(serverAddr6)) == -1)
        {
            perror("Bind failed");
            return -1;
        }
    }
    else
    {
        printf("Invalid address type\n");
        return -1;
    }

    return serverSocket;
}

int bind_udp_server_socket(int serverSocket, enum addr type, const char *port)
{
    struct sockaddr_in serverAddr;
    struct sockaddr_in6 serverAddr6;

    if (type == IPV4)
    {
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(atoi(port));

        if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
        {
            printf("\nBind failed\n");
            return -1;
        }
    }
    else if (type == IPV6)
    {
        memset(&serverAddr6, 0, sizeof(serverAddr6));
        serverAddr6.sin6_family = AF_INET6;
        serverAddr6.sin6_addr = in6addr_any;
        serverAddr6.sin6_port = htons(atoi(port));

        if (bind(serverSocket, (struct sockaddr *)&serverAddr6, sizeof(serverAddr6)) < 0)
        {
            printf("\nBind failed\n");
            return -1;
        }
    }

    return 0;
}

int receive_checksum(int serverSocket, enum addr type, unsigned char *recv_hash)
{
    struct sockaddr_in clientAddr;
    struct sockaddr_in6 clientAddr6;
    socklen_t clientAddressLen;

    char hash_str[SHA_DIGEST_LENGTH * 2 + 1];
    int bytes;

    if (type == IPV4)
    {
        bytes = recvfrom(serverSocket, hash_str, sizeof(hash_str), 0, (struct sockaddr *)&clientAddr, &clientAddressLen);
    }
    else if (type == IPV6)
    {
        bytes = recvfrom(serverSocket, hash_str, sizeof(hash_str), 0, (struct sockaddr *)&clientAddr6, &clientAddressLen);
    }

    if (bytes < 0)
    {
        printf("recv failed. Sender inactive.\n");
        return -1;
    }

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        sscanf(&hash_str[i * 2], "%2hhx", &recv_hash[i]);
    }

    return 0;
}

int init_udp_server(int argc, char *argv[], enum addr type)
{
    struct timeval start, end;
    int serverSocket;
    socklen_t clientAddressLen;
    struct sockaddr_in serverAddr, clientAddr;
    struct sockaddr_in6 serverAddr6, clientAddr6;
    int bytes = 0, countbytes = 0;
    char buffer[BUF_SIZE] = {0}, decoded[BUF_SIZE], *totalData = malloc(DATA_SIZE);
    serverSocket = create_udp_server_socket(argc, argv, type);
    if (serverSocket < 0)
    {
        printf("\nSocket creation error\n");
        return -1;
    }

    if (bind_udp_server_socket(serverSocket, type, argv[2]) < 0)
    {
        close(serverSocket);
        return -1;
    }

    unsigned char recv_hash[SHA_DIGEST_LENGTH];
    if (receive_checksum(serverSocket, type, recv_hash) < 0)
    {
        close(serverSocket);
        return -1;
    }

    gettimeofday(&start, NULL);

    while (1)
    {
        if (type == IPV4)
        {
            bytes = recvfrom(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&clientAddr, &clientAddressLen);
        }
        else if (type == IPV6)
        {
            bytes = recvfrom(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&clientAddr6, &clientAddressLen);
        }

        if (bytes < 0)
        {
            printf("recv failed. Sender inactive.\n");
            close(serverSocket);
            return -1;
        }

        if (bytes < 0)
        {
            buffer[bytes] = '\0';
            strncpy(decoded, buffer, sizeof(decoded));
            if (strcmp(decoded, "END") == 0)
            {
                break;
            }
        }

        memcpy(totalData + countbytes, buffer, bytes);
        countbytes += bytes;
    }

    gettimeofday(&end, NULL);
    unsigned long milliseconds = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;

    unsigned char calculated_hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)totalData, strlen(totalData), calculated_hash);

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        if (calculated_hash[i] != recv_hash[i])
        {
            printf("Checksums don't match\n");
            break;
        }
    }

    if (type == IPV4)
    {
        printf("ipv4_udp,%lu\n", milliseconds);
    }
    else
    {
        printf("ipv6_udp,%lu\n", milliseconds);
    }

    close(serverSocket);
    free(totalData);
    return 0;
}

int uds_dgram_client(int argc, char *argv[])
{
    int sendStream = 0, totalSent = 0;
    char buffer[BUF_SIZE] = {0};
    struct timeval start, end;
    char *serverType = "udsd";
    char *endMsg = "END";
    send_type_to_server(argc, argv, serverType);

    int sock;
    struct sockaddr_un server_addr, client_address;

    // Create sending socket
    if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
    {
        printf("Failed to create sending socket\n");
        return -1;
    }

    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SERVER_SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // Create receiving socket
    memset(&client_address, 0, sizeof(struct sockaddr_un));
    client_address.sun_family = AF_UNIX;
    strncpy(client_address.sun_path, CLIENT_SOCKET_PATH, sizeof(client_address.sun_path) - 1);
    remove(client_address.sun_path);

    printf("Client started\n");

    // Generate data
    char *data = generate_rand_str(DATA_SIZE);

    // Calculate and send checksum
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)data, strlen(data), hash);
    char hash_str[SHA_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }
    hash_str[SHA_DIGEST_LENGTH * 2] = '\0';

    sendStream = sendto(sock, hash_str, strlen(hash_str), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (sendStream == -1)
    {
        printf("send() failed\n");
        return -1;
    }

    // Send data
    int i = 0;
    gettimeofday(&start, 0);
    while (totalSent < strlen(data))
    {
        int bytes_to_send = (BUF_SIZE < strlen(data) - totalSent) ? BUF_SIZE : strlen(data) - totalSent;
        memcpy(buffer, data + totalSent, bytes_to_send);

        sendStream = sendto(sock, buffer, bytes_to_send, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (sendStream == -1)
        {
            printf("send() failed\n");
            return -1;
        }

        totalSent += sendStream;
        if (i % 200 == 0 || bytes_to_send < BUF_SIZE)
        {
            printf("Total bytes sent: %d\n", totalSent);
        }
        i++;

        bzero(buffer, sizeof(buffer));
    }

    gettimeofday(&end, 0);
    strcpy(buffer, endMsg);
    sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    unsigned long milliseconds = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
    printf("Total bytes sent: %d\nTime elapsed: %lu milliseconds\n", totalSent, milliseconds);

    // Close socket and clean up
    close(sock);
    unlink(CLIENT_SOCKET_PATH);
    return 0;
}
