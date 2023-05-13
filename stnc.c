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

int uds_dgram_server(int argc, char *argv[])
{
    int server_fd;
    struct sockaddr_un server_addr, client_addr;
    socklen_t clientAddressLen;
    int bytes = 0, countbytes = 0;
    char buffer[BUF_SIZE] = {0};
    char decoded[BUF_SIZE];
    char *totalData = malloc(DATA_SIZE);
    struct timeval start, end;

    // Create server socket
    if ((server_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
    {
        printf("Failed to create server socket\n");
        return -1;
    }

    remove(SERVER_SOCKET_PATH);

    // Initialize server address
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SERVER_SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // Bind server socket to address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) == -1)
    {
        printf("Failed to bind server socket to address\n");
        return -1;
    }

    // Receive checksum
    char hash_str[SHA_DIGEST_LENGTH * 2 + 1];
    bytes = recvfrom(server_fd, hash_str, sizeof(hash_str), 0, (struct sockaddr *)&client_addr, &clientAddressLen);
    if (bytes < 0)
    {
        printf("recv failed. Sender inactive.\n");
        close(server_fd);
        return -1;
    }

    unsigned char recv_hash[SHA_DIGEST_LENGTH];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        sscanf(&hash_str[i * 2], "%2hhx", &recv_hash[i]);
    }

    // Receive data
    gettimeofday(&start, NULL);
    while (1)
    {
        bytes = recvfrom(server_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &clientAddressLen);
        if (bytes < 0)
        {
            printf("recv failed. Sender inactive.\n");
            close(server_fd);
            return -1;
        }

        if (bytes < 10)
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

    // Calculate checksum
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

    printf("uds_dgram,%lu\n", milliseconds);

    close(server_fd);
    free(totalData);
    unlink(SERVER_SOCKET_PATH);

    return 0;
}

int mmap_client(int argc, char *argv[])
{
    char *serverType = "mmap";

    // Generate file
    char *data = generate_rand_str(DATA_SIZE);
    int dataLen = strlen(data);

    FILE *filePtr = fopen(argv[6], "w");
    if (filePtr == NULL)
    {
        printf("Error opening file!\n");
        return -1;
    }
    fprintf(filePtr, "%s", data);
    fclose(filePtr);

    int fd = open(argv[6], O_RDONLY);
    if (fd == -1)
    {
        printf("open() failed\n");
        return -1;
    }

    void *fileAddr = mmap(NULL, dataLen, PROT_READ, MAP_PRIVATE, fd, 0);
    if (fileAddr == MAP_FAILED)
    {
        printf("mmap() failed\n");
        return -1;
    }
    close(fd);

    // Calculate and save checksum
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)data, strlen(data), hash);
    free(data);

    int shmFd = shm_open(SHM_FILE, O_CREAT | O_RDWR, 0666);
    int shmFdName = shm_open(SHM_FILE_NAME, O_CREAT | O_RDWR, 0666);
    int shmFdChecksum = shm_open(SHM_FILE_CS, O_CREAT | O_RDWR, 0666);
    if (shmFd == -1 || shmFdName == -1 || shmFdChecksum == -1)
    {
        perror("shm_open() failed\n");
        return -1;
    }

    int res = ftruncate(shmFd, dataLen);
    int res2 = ftruncate(shmFdName, strlen(argv[6]));
    int res3 = ftruncate(shmFdChecksum, sizeof(hash));
    if (res == -1 || res2 == -1 || res3 == -1)
    {
        printf("ftruncate() failed\n");
        return -1;
    }

    void *shmAddr = mmap(NULL, dataLen, PROT_WRITE, MAP_SHARED, shmFd, 0);
    void *shmNameAddr = mmap(NULL, strlen(argv[6]), PROT_WRITE, MAP_SHARED, shmFdName, 0);
    void *shmChecksumAddr = mmap(NULL, sizeof(hash), PROT_WRITE, MAP_SHARED, shmFdChecksum, 0);
    if (shmAddr == MAP_FAILED || shmNameAddr == MAP_FAILED || shmChecksumAddr == MAP_FAILED)
    {
        printf("mmap() failed\n");
        return -1;
    }

    memcpy(shmAddr, fileAddr, dataLen);
    memcpy(shmNameAddr, argv[6], strlen(argv[6]));
    memcpy(shmChecksumAddr, hash, sizeof(hash));

    munmap(fileAddr, dataLen);
    munmap(shmAddr, dataLen);
    munmap(shmNameAddr, strlen(argv[6]));
    munmap(shmChecksumAddr, sizeof(hash));
    close(shmFd);
    close(shmFdName);
    close(shmFdChecksum);

    send_type_to_server(argc, argv, serverType);
    return 0;
}

int mmap_server(int argc, char *argv[])
{
    // Retrieve shared memory object
    struct timeval start, end;
    gettimeofday(&start, NULL);

    int shmFd = shm_open(SHM_FILE, O_RDONLY, 0666);
    if (shmFd == -1)
    {
        perror("shm_open() failed\n");
        return -1;
    }

    struct stat shmInfo;
    if (fstat(shmFd, &shmInfo) == -1)
    {
        printf("fstat() failed\n");
        return -1;
    }

    int shmSize = shmInfo.st_size;
    void *shmAddr = mmap(NULL, shmSize, PROT_READ, MAP_SHARED, shmFd, 0);
    close(shmFd);

    if (shmAddr == MAP_FAILED)
    {
        printf("mmap() failed\n");
        return -1;
    }

    // Copy data from shared memory
    char *receivedData = malloc(shmSize);
    char *pData = (char *)shmAddr;
    for (int i = 0; i < shmSize; i++)
    {
        receivedData[i] = pData[i];
    }

    gettimeofday(&end, NULL);

    // Retrieve and compare checksums
    int shmChecksumFd = shm_open(SHM_FILE_CS, O_RDONLY, 0666);
    if (shmChecksumFd == -1)
    {
        perror("shm_open() failed\n");
        return -1;
    }

    struct stat checksumInfo;
    if (fstat(shmChecksumFd, &checksumInfo) == -1)
    {
        printf("fstat() failed\n");
        return -1;
    }

    int checksumSize = checksumInfo.st_size;
    void *checksumAddr = mmap(NULL, checksumSize, PROT_READ, MAP_SHARED, shmChecksumFd, 0);

    if (checksumAddr == MAP_FAILED)
    {
        printf("mmap() failed\n");
        return -1;
    }

    close(shmChecksumFd);

    unsigned char calculatedHash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)receivedData, strlen(receivedData), calculatedHash);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        if (calculatedHash[i] != ((unsigned char *)checksumAddr)[i])
        {
            printf("Checksums don't match\n");
            break;
        }
    }

    shm_unlink(SHM_FILE);
    shm_unlink(SHM_FILE_CS);
    free(receivedData);

    unsigned long milliseconds = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
    printf("mmap,%lu\n", milliseconds);

    munmap(shmAddr, shmSize);

    // Remove file associated with shared memory
    int shmNameFd = shm_open(SHM_FILE_NAME, O_RDONLY, 0666);
    if (shmNameFd == -1)
    {
        perror("shm_open() failed\n");
        return -1;
    }

    struct stat nameInfo;
    if (fstat(shmNameFd, &nameInfo) == -1)
    {
        printf("fstat() failed\n");
        return -1;
    }

    off_t nameSize = nameInfo.st_size;
    void *nameAddr = mmap(NULL, nameSize, PROT_READ, MAP_SHARED, shmNameFd, 0);

    if (nameAddr == MAP_FAILED)
    {
        printf("mmap() failed\n");
        return -1;
    }

    close(shmNameFd);

    int status = remove((char *)nameAddr);
    if (status != 0)
    {
        printf("Unable to delete the file\n");
    }

    munmap(nameAddr, nameSize);

    if (shm_unlink(SHM_FILE_NAME) == -1)
    {
        printf("shm_unlink() failed\n");
        return -1;
    }

    return 0;
}

int pipe_client(int argc, char *argv[])
{
    int pipe_fd;
    char buffer[TCP_BUF_SIZE];
    int bytes_read;
    char *data = generate_rand_str(DATA_SIZE);

    // Calculate and save checksum into shared memory
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)data, strlen(data), hash);

    int shm_fd_checksum = shm_open(SHM_FILE_CS, O_CREAT | O_RDWR, 0666);
    if (shm_fd_checksum == -1)
    {
        perror("shm_open() failed\n");
        return -1;
    }

    int res = ftruncate(shm_fd_checksum, sizeof(hash));
    if (res == -1)
    {
        printf("ftruncate() failed\n");
        return -1;
    }

    void *shm_checksum_addr = mmap(NULL, sizeof(hash), PROT_WRITE, MAP_SHARED, shm_fd_checksum, 0);
    if (shm_checksum_addr == MAP_FAILED)
    {
        printf("mmap() failed\n");
        return -1;
    }
    memcpy(shm_checksum_addr, &hash, sizeof(hash));
    munmap(shm_checksum_addr, sizeof(hash));
    close(shm_fd_checksum);

    // Send type to server
    send_type_to_server(argc, argv, "pipe");

    // Open the named pipe for writing
    pipe_fd = open(FIFO_NAME, O_WRONLY);
    if (pipe_fd < 0)
    {
        perror("Error: Could not open named pipe\n");
        exit(1);
    }

    // Write data to the named pipe
    FILE *file_write = fopen(argv[6], "w");
    if (file_write == NULL)
    {
        printf("Error opening file!\n");
        return -1;
    }
    fprintf(file_write, "%s", data);
    fclose(file_write);

    FILE *file_read = fopen(argv[6], "r");
    if (file_read == NULL)
    {
        printf("Error opening file!\n");
        return -1;
    }
    while ((bytes_read = fread(buffer, 1, TCP_BUF_SIZE, file_read)) > 0)
    {
        if (write(pipe_fd, buffer, bytes_read) < 0)
        {
            fprintf(stderr, "Error: Could not write to named pipe\n");
            exit(1);
        }
    }
    if (remove(argv[6]) != 0)
    {
        printf("File %s was not deleted.\n", argv[6]);
    }
    close(pipe_fd);
    free(data);
    fclose(file_read);
    return 0;
}

int pipe_server(int argc, char *argv[])
{
    int fifoFileDescriptor, countBytes = 0;
    char buf[TCP_BUF_SIZE], *totalData = malloc(DATA_SIZE);
    struct timeval startTime, endTime;

    mkfifo(FIFO_NAME, 0666);
    fifoFileDescriptor = open(FIFO_NAME, O_RDONLY);
    if (fifoFileDescriptor < 0)
    {
        fprintf(stderr, "Error: Could not open named pipe\n");
        exit(1);
    }

    int bytesRead = 0;

    // Get checksum from shared memory
    int sharedMemoryChecksumFd = shm_open(SHM_FILE_CS, O_RDONLY, 0666);
    if (sharedMemoryChecksumFd == -1)
    {
        perror("shm_open() failed\n");
        return -1;
    }
    struct stat sharedMemoryChecksumStat;
    if (fstat(sharedMemoryChecksumFd, &sharedMemoryChecksumStat) == -1)
    {
        printf("fstat() failed\n");
        return -1;
    }
    int checksumLength = sharedMemoryChecksumStat.st_size;
    void *checksumAddress = mmap(NULL, checksumLength, PROT_READ, MAP_SHARED, sharedMemoryChecksumFd, 0);
    if (checksumAddress == MAP_FAILED)
    {
        printf("mmap() failed\n");
        return -1;
    }
    close(sharedMemoryChecksumFd);

    // Read from FIFO
    gettimeofday(&startTime, 0);
    while ((bytesRead = read(fifoFileDescriptor, buf, TCP_BUF_SIZE)) > 0)
    {
        memcpy(totalData + countBytes, buf, bytesRead);
        countBytes += bytesRead;
        // printf("TotalData size: %ld\n", strlen(totalData));
    }
    gettimeofday(&endTime, 0);

    // Calculate and compare checksums
    unsigned char calculatedHash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)totalData, strlen(totalData), calculatedHash);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        if (calculatedHash[i] != ((unsigned char *)checksumAddress)[i])
        {
            printf("Checksums don't match\n");
            break;
        }
    }

    unsigned long milliseconds = (endTime.tv_sec - startTime.tv_sec) * 1000 + (endTime.tv_usec - startTime.tv_usec) / 1000;
    printf("pipe,%lu\n", milliseconds);
    close(fifoFileDescriptor);
    unlink(FIFO_NAME);
    shm_unlink(SHM_FILE_CS);
    free(totalData);
    return 0;
}

int tcp_server(int argc, char *argv[], enum addr type)
{
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddress, clientAddress;
    struct sockaddr_in6 serverAddress6, clientAddress6;
    socklen_t clientAddressLen;
    int option = 1, bytes = -1, totalBytes = 0;
    char receiveBuffer[TCP_BUF_SIZE] = {0};
    char *totalData = malloc(DATA_SIZE);
    struct timeval startTime, endTime;

    if (type == IPV4)
    {
        // Create server socket
        if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            printf("\nSocket creation error\n");
            return -1;
        }

        memset(&serverAddress, 0, sizeof(serverAddress));
        memset(&clientAddress, 0, sizeof(clientAddress));
        clientAddressLen = sizeof(clientAddress);

        // Set socket address
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_addr.s_addr = INADDR_ANY;
        serverAddress.sin_port = htons(atoi(argv[2]));

        // Set socket options
        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)))
        {
            printf("\nSetsockopt error\n");
            return -1;
        }

        // Bind socket to address
        if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        {
            perror("\nTCP bind failed\n");
            return -1;
        }
    }
    else if (type == IPV6)
    {
        // Create server socket
        if ((serverSocket = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
        {
            printf("\nSocket creation error\n");
            return -1;
        }

        memset(&serverAddress6, 0, sizeof(serverAddress6));
        memset(&clientAddress6, 0, sizeof(clientAddress6));
        clientAddressLen = sizeof(clientAddress6);

        // Set socket address
        serverAddress6.sin6_family = AF_INET6;
        serverAddress6.sin6_addr = in6addr_any;
        serverAddress6.sin6_port = htons(atoi(argv[2]));

        // Set socket options
        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)))
        {
            printf("\nSetsockopt error\n");
            return -1;
        }

        // Bind socket to address
        if (bind(serverSocket, (struct sockaddr *)&serverAddress6, sizeof(serverAddress6)) < 0)
        {
            printf("\nTCP bind failed\n");
            return -1;
        }
    }
    else
    {
        printf("Invalid address type\n");
        return -1;
    }

    // Listen for incoming connections
    if (listen(serverSocket, 3) < 0)
    {
        printf("\nListen error\n");
        return -1;
    }
    if (type == IPV4)
    {
        if ((clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLen)) < 0)
        {
            printf("\nAccept error\n");
            return -1;
        }
    }
    else if (type == IPV6)
    {
        if ((clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress6, &clientAddressLen)) < 0)
        {
            printf("\nAccept error\n");
            return -1;
        }
    }

    // Receive checksum
    char receivedHashStr[SHA_DIGEST_LENGTH * 2 + 1];
    bytes = recv(clientSocket, receivedHashStr, sizeof(receivedHashStr), 0);
    if (bytes < 0)
    {
        printf("Recv failed. Sender inactive.\n");
        close(serverSocket);
        close(clientSocket);
        return -1;
    }
    unsigned char receivedHash[SHA_DIGEST_LENGTH];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        sscanf(&receivedHashStr[i * 2], "%2hhx", &receivedHash[i]);
    }

    gettimeofday(&startTime, 0);
    while (bytes != 0)
    {
        if ((bytes = recv(clientSocket, receiveBuffer, sizeof(receiveBuffer), 0)) < 0)
        {
            printf("Recv failed. Sender inactive.\n");
            // close(serverSocket);
            // close(clientSocket);
            return -1;
        }
        memcpy(totalData + totalBytes, receiveBuffer, bytes);
        totalBytes += bytes;
    }
    gettimeofday(&endTime, 0);
    unsigned long milliseconds = (endTime.tv_sec - startTime.tv_sec) * 1000 + (endTime.tv_usec - startTime.tv_usec) / 1000;

    // Calculate checksum
    unsigned char calculatedHash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)totalData, strlen(totalData), calculatedHash);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        if (calculatedHash[i] != receivedHash[i])
        {
            printf("Checksums don't match\n");
            break;
        }
    }

    if (type == IPV4)
    {
        printf("ipv4_tcp,%lu\n", milliseconds);
    }
    else
    {
        printf("ipv6_tcp,%lu\n", milliseconds);
    }

    // Close server socket
    close(serverSocket);
    close(clientSocket);
    free(totalData);
    return 0;
}