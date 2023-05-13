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
#include "stnc.h"

#define UNIX_SOCKET_PATH "/tmp/my_socket.sock"
#define UNIX_SERVER_SOCKET_PATH "/tmp/uds_dgram_server"
#define UNIX_CLIENT_SOCKET_PATH "/tmp/uds_dgram_client"
#define SHM_FILE_PATH "/FileSM"
#define SHM_FILE_NAME "/FileName"
#define SHM_FILE_CS_NAME "/FileCS"
#define FIFO_PATH "/tmp/myfifo"
#define MAX_DATA_SIZE 100000000
#define MAX_BUFFER_SIZE 64000
#define MAX_TCP_BUFFER_SIZE 1000000


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

/**
 * @brief handleClient - Handles client connections based on the specified command-line arguments.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line arguments.
 */
void handleClient(int argc, char *argv[])
{
    // Check if the 5th element in the argv array is NULL
    if (argv[4] == NULL)
    {
        // If it is, initialize a client using the "init_client" function
        init_client(argc, argv);
    }
    // If the 5th element is not NULL, check if it is equal to "-p"
    else if (!strcmp(argv[4], "-p"))
    {
        // If it is "-p", check the value of the 6th element in the argv array to determine the type of client
        if (!strcmp(argv[5], "ipv4"))
        {
            // If the 6th element is "ipv4", check the value of the 7th element to determine the protocol type (TCP or UDP)
            if (!strcmp(argv[6], "tcp"))
            {
                // If the 7th element is "tcp", initialize a TCP client using the "tcp_client" function with the IPV4 flag
                tcp_client(argc, argv, IPV4);
            }
            else if (!strcmp(argv[6], "udp"))
            {
                // If the 7th element is "udp", initialize a UDP client using the "init_udp_client" function with the IPV4 flag
                init_udp_client(argc, argv, IPV4);
            }
        }
        else if (!strcmp(argv[5], "ipv6"))
        {
            // If the 6th element is "ipv6", check the value of the 7th element to determine the protocol type (TCP or UDP)
            if (!strcmp(argv[6], "tcp"))
            {
                // If the 7th element is "tcp", initialize a TCP client using the "tcp_client" function with the IPV6 flag
                tcp_client(argc, argv, IPV6);
            }
            else if (!strcmp(argv[6], "udp"))
            {
                // If the 7th element is "udp", initialize a UDP client using the "init_udp_client" function with the IPV6 flag
                init_udp_client(argc, argv, IPV6);
            }
        }
        else if (!strcmp(argv[5], "uds"))
        {
            // If the 6th element is "uds", check the value of the 7th element to determine the type of Unix domain socket (stream or datagram)
            if (!strcmp(argv[6], "stream"))
            {
                // If the 7th element is "stream", initialize a Unix domain socket stream client using the "uds_stream_client" function
                uds_stream_client(argc, argv);
            }
            else if (!strcmp(argv[6], "dgram"))
            {
                // If the 7th element is "dgram", initialize a Unix domain socket datagram client using the "uds_dgram_client" function
                uds_dgram_client(argc, argv);
            }
        }
        else if (!strcmp(argv[5], "mmap"))
        {
            // If the 6th element is "mmap", initialize a client using the "mmap_client" function
            mmap_client(argc, argv);
        }
        else if (!strcmp(argv[5], "pipe"))
        {
            // If the 6th element is "pipe", initialize a client using the "pipe_client" function
            pipe_client(argc, argv);
        }
    }
}



/**
 * @brief handleServer - Handles server connections based on the specified command-line arguments.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line arguments.
 */
void handleServer(int argc, char *argv[])
{
    // Check if the server type is specified in the command-line arguments
    if (argv[3] != NULL)
    {
        // Get the server type based on the command-line arguments
        char *serverType = getServerType(argc, argv);

        // Depending on the server type, call the corresponding server function
        if (strcmp(serverType, "tcp4") == 0)
        {
            tcp_server(argc, argv, IPV4);
        }
        else if (strcmp(serverType, "tcp6") == 0)
        {
            tcp_server(argc, argv, IPV6);
        }
        else if (strcmp(serverType, "udp4") == 0)
        {
            init_udp_server(argc, argv, IPV4);
        }
        else if (strcmp(serverType, "udp6") == 0)
        {
            init_udp_server(argc, argv, IPV6);
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

        // Free the memory allocated for the server type string
        free(serverType);
    }
    // If the server type is not specified, call the generic server function
    else
    {
        server(argc, argv);
    }
}


/**

* @brief init_client - Initializes a TCP client and establishes a connection to a server at the specified IP address and port number.
*
* @param argc The number of command line arguments.
* @param argv The command line arguments. argv[2] should be the IP address of the server, argv[3] should be the port number.
* @return Returns 0 upon successful completion.
*/
int init_client(int argc, char *argv[])
{
    // Create a socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1)
    {
        perror("--Error--socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set the server address
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

    // Connect to the server
    if (connect(socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        perror("--Error--connection failed");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server Connection Established!\n");

    // Initialize variables for use with select()
    fd_set readfds;
    char message[MAX_BUFFER_SIZE];

    // Enter a loop to send and receive messages to and from the server
    while (1)
    {
        // Reset the read file descriptors and set them for use with select()
        FD_ZERO(&readfds);
        FD_SET(socket_fd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);

        // Set a timeout of 10 seconds
        struct timeval timeout =
            {
                .tv_sec = 10,
                .tv_usec = 0,
            };

        // Determine the maximum file descriptor and wait for input
        int maxfd = (socket_fd > STDIN_FILENO) ? socket_fd : STDIN_FILENO;
        int res = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
        if (res == -1)
        {
            perror("--Error--in select");
            exit(EXIT_FAILURE);
        }
        else if (res == 0)
        {
            // Timeout occurred, continue waiting
            continue;
        }
        else
        {
            // Check if there is input from the user
            if (FD_ISSET(STDIN_FILENO, &readfds))
            {
                // Read the user input
                if (fgets(message, MAX_BUFFER_SIZE, stdin) == NULL)
                {
                    perror("--Error--reading input");
                    exit(EXIT_FAILURE);
                }

                // Send the user input to the server
                int bytes = send(socket_fd, message, strlen(message), 0);
                if (bytes == -1)
                {
                    perror("--Error--sending message");
                    exit(EXIT_FAILURE);
                }
            }

            // Check if there is input from the server
            if (FD_ISSET(socket_fd, &readfds))
            {
                // Receive a message from the server
                int bytes = recv(socket_fd, message, MAX_BUFFER_SIZE, 0);
                if (bytes == -1)
                {
                    perror("--Error--receiving message");
                    exit(EXIT_FAILURE);
                }
                else if (bytes == 0)
                {
                    // The server closed the connection
                    printf("server closed the connection\n");
                    break;
                }
                else
                {
                    // Display the message from the server
                    message[bytes] = '\0';
                    printf("Server msg: %s", message);
                }
            }
        }
    }

    // Close the socket and return
    close(socket_fd);
    return 0;
}


/**
 * @brief init_udp_client - Initializes a UDP client and sends data to a server.
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
    char buffer[MAX_BUFFER_SIZE] = {0};
    struct timeval startTime, endTime;
    const char *endMsg = "END";

    // Create socket
    if (type == IPV4)
    {
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
        {
            printf("\n--Error--Can not create Socket \n");
            return -1;
        }

        memset(&servAddress4, 0, sizeof(servAddress4));

        // Set socket address
        servAddress4.sin_family = AF_INET;
        servAddress4.sin_port = htons(atoi(argv[3]));

        // Convert IPv4 and store in sin_addr
        if (inet_pton(AF_INET, argv[2], &servAddress4.sin_addr) <= 0)
        {
            printf("\n--Error--Invalid address/Address not supported\n");
            return -1;
        }
    }
    else if (type == IPV6)
    {
        sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sock < 0)
        {
            printf("\n--Error--Socket Can not be created\n");
            return -1;
        }

        memset(&servAddress6, 0, sizeof(servAddress6));

        // Set socket address
        servAddress6.sin6_family = AF_INET6;
        servAddress6.sin6_port = htons(atoi(argv[3]));

        // Convert IPv4 and store in sin_addr
        if (inet_pton(AF_INET6, argv[2], &servAddress6.sin6_addr) <= 0)
        {
            printf("\n--Error--Invalid address/Address not supported\n");
            return -1;
        }
    }
    else
    {
        printf("--Error--Invalid address type\n");
        return -1;
    }

    // Generate data
    char *data = generate_rand_str(MAX_DATA_SIZE);

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
        printf("--Error--send() failed");
        exit(1);
    }

    gettimeofday(&startTime, 0);
    int i = 0;
    while (totalSent < strlen(data))
    {
        int bytesToSend = (MAX_BUFFER_SIZE < strlen(data) - totalSent) ? MAX_BUFFER_SIZE : (int)(strlen(data) - totalSent);
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
            printf("--Error--send() failed");
            exit(1);
        }

        totalSent += sendStream;
        if (i % 200 == 0 || bytesToSend < MAX_BUFFER_SIZE)
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


/**
* @brief create_udp_server_socket - Creates and binds a UDP server socket.
*
* @param argc The number of arguments in argv.
* @param argv An array of strings containing the arguments.
* @param type An enum indicating whether to use IPv4 or IPv6.
* @return The socket file descriptor on success, or -1 on failure.
*/
int create_udp_server_socket(int argc, char *argv[], enum addr type)
{
    // Declare variables for server and client addresses and socket descriptors
    struct sockaddr_in serverAddr, clientAddr;
    struct sockaddr_in6 serverAddr6, clientAddr6;
    socklen_t clientAddressLen;
    int serverSocket;

    // If the address type is IPv4
    if (type == IPV4)
    {
        // Create a new server socket with IPv4
        if ((serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
            // If there's an error, print a message and return -1
            perror("--Error--Socket could not be created");
            return -1;
        }

        // Zero out server and client address variables
        memset(&serverAddr, 0, sizeof(serverAddr));
        memset(&clientAddr, 0, sizeof(clientAddr));

        // Set server address information
        serverAddr.sin_family = AF_INET; // Set the address family to IPv4
        serverAddr.sin_addr.s_addr = INADDR_ANY; // Use any available network interface
        serverAddr.sin_port = htons(atoi(argv[2])); // Set the port number from the command line

        // Bind the server socket to the server address
        if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
        {
            // If there's an error, print a message and return -1
            perror("--Error--Bind failed");
            return -1;
        }
    }
    // If the address type is IPv6
    else if (type == IPV6)
    {
        // Create a new server socket with IPv6
        if ((serverSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
            // If there's an error, print a message and return -1
            perror("--Error--Socket could not be created");
            return -1;
        }

        // Zero out server and client address variables
        memset(&serverAddr6, 0, sizeof(serverAddr6));
        memset(&clientAddr6, 0, sizeof(clientAddr6));

        // Set server address information
        serverAddr6.sin6_family = AF_INET6; // Set the address family to IPv6
        serverAddr6.sin6_addr = in6addr_any; // Use any available network interface
        serverAddr6.sin6_port = htons(atoi(argv[2])); // Set the port number from the command line

        // Bind the server socket to the server address
        if (bind(serverSocket, (struct sockaddr *)&serverAddr6, sizeof(serverAddr6)) == -1)
        {
            // If there's an error, print a message and return -1
            perror("--Error--Bind failed");
            return -1;
        }
    }
    // If the address type is neither IPv4 nor IPv6
    else
    {
        // Print an error message and return -1
        printf("--Error--Invalid address type\n");
        return -1;
    }

    // Return the server socket descriptor
    return serverSocket;
}


/**
* @brief bind_udp_server_socket - Binds the given UDP server socket to the specified port and address family.
*
* @param serverSocket The server socket to bind.
* @param type The address family to use (IPV4 or IPV6).
* @param port The port to bind the server socket to.
* @return Returns 0 on success, or -1 on failure.
*/
int bind_udp_server_socket(int serverSocket, enum addr type, const char *port)
{
    struct sockaddr_in serverAddr;
    struct sockaddr_in6 serverAddr6;

    // If IP version is IPv4
    if (type == IPV4)
    {
        // Initialize the IPv4 socket address structure
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY; // Bind to all available network interfaces
        serverAddr.sin_port = htons(atoi(port)); // Set port number

        // Bind the server socket to the IPv4 socket address structure
        if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
        {
            printf("\n--Error--Bind failed\n");
            return -1;
        }
    }
    // If IP version is IPv6
    else if (type == IPV6)
    {
        // Initialize the IPv6 socket address structure
        memset(&serverAddr6, 0, sizeof(serverAddr6));
        serverAddr6.sin6_family = AF_INET6;
        serverAddr6.sin6_addr = in6addr_any; // Bind to all available network interfaces
        serverAddr6.sin6_port = htons(atoi(port)); // Set port number

        // Bind the server socket to the IPv6 socket address structure
        if (bind(serverSocket, (struct sockaddr *)&serverAddr6, sizeof(serverAddr6)) < 0)
        {
            printf("\n--Error--Bind failed\n");
            return -1;
        }
    }

    return 0;
}



/**
* @brief receive_checksum - Receives a checksum from a client through a UDP socket.
*
* @param serverSocket The UDP socket to receive the checksum from.
* @param type The type of address the socket is bound to, either IPV4 or IPV6.
* @param recv_hash A pointer to a buffer to store the received checksum.
* @return 0 if successful, -1 otherwise.
*/
int receive_checksum(int serverSocket, enum addr type, unsigned char *recv_hash)
{
    struct sockaddr_in clientAddr;
    struct sockaddr_in6 clientAddr6;
    socklen_t clientAddressLen;

    char hash_str[SHA_DIGEST_LENGTH * 2 + 1];
    int bytes;

    if (type == IPV4)
    {
        // Receive data from the client using the serverSocket and client address
        bytes = recvfrom(serverSocket, hash_str, sizeof(hash_str), 0, (struct sockaddr *)&clientAddr, &clientAddressLen);
    }
    else if (type == IPV6)
    {
        // Receive data from the client using the serverSocket and client address
        bytes = recvfrom(serverSocket, hash_str, sizeof(hash_str), 0, (struct sockaddr *)&clientAddr6, &clientAddressLen);
    }

    if (bytes < 0)
    {
        printf("--Error--recv failed. Sender inactive.\n");
        return -1;
    }

    // Convert hash string to unsigned char array
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        sscanf(&hash_str[i * 2], "%2hhx", &recv_hash[i]);
    }

    return 0;
}


/**
* @brief init_udp_server - Initializes a UDP server and receives data from a client until the "END" message is received.
*
* @param argc the number of arguments passed to the program
* @param argv an array of strings containing the arguments passed to the program
* @param type the type of IP address being used (IPV4 or IPV6)
* @return 0 if successful, -1 if there was an error
*/
int init_udp_server(int argc, char *argv[], enum addr type)
{
    struct timeval start, end;
    int serverSocket;
    socklen_t clientAddressLen;
    struct sockaddr_in serverAddr, clientAddr;
    struct sockaddr_in6 serverAddr6, clientAddr6;
    int bytes = 0, countbytes = 0;
    char buffer[MAX_BUFFER_SIZE] = {0}, decoded[MAX_BUFFER_SIZE], *totalData = malloc(MAX_DATA_SIZE);
    // Create a UDP server socket
    serverSocket = create_udp_server_socket(argc, argv, type);
    // Check if the socket creation was successful
    if (serverSocket < 0)
    {
        printf("\n--Error--Socket could not be created\n");
        return -1;
    }

    // Bind the server socket to the specified address and port
    if (bind_udp_server_socket(serverSocket, type, argv[2]) < 0)
    {
        close(serverSocket);
        return -1;
    }
    // Receive the checksum from the client
    unsigned char recv_hash[SHA_DIGEST_LENGTH];
    if (receive_checksum(serverSocket, type, recv_hash) < 0)
    {
        close(serverSocket);
        return -1;
    }
    // Get the start time of the data transfer
    gettimeofday(&start, NULL);

    // Loop to receive data from client
    while (1)
    {
        if (type == IPV4)
        {
            bytes = recvfrom(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&clientAddr, &clientAddressLen); // Receive data
        }
        else if (type == IPV6)
        {
            bytes = recvfrom(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&clientAddr6, &clientAddressLen);   // Receive data
        }

        if (bytes < 0)
        {
            printf("--Error--recv failed. Sender inactive.\n");   // Error handling
            close(serverSocket);                        // Close socket
            return -1;
        }

        if (bytes < 0)
        {
            buffer[bytes] = '\0';       // Null-terminate buffer
            strncpy(decoded, buffer, sizeof(decoded));   // Copy data from buffer to decoded buffer
            if (strcmp(decoded, "END") == 0)   // Check for end of transmission
            {
                break;                      // Break loop
            }
        }

        memcpy(totalData + countbytes, buffer, bytes);    // Copy data from buffer to totalData buffer
        countbytes += bytes;                                // Increment count of bytes
    }

    gettimeofday(&end, NULL);                          // End timing
    unsigned long milliseconds = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;  // Calculate elapsed time
    unsigned char calculated_hash[SHA_DIGEST_LENGTH];          // Buffer for calculated hash
    SHA1((unsigned char *)totalData, strlen(totalData), calculated_hash);  // Calculate hash for received data

    // Check if received hash matches calculated hash
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        if (calculated_hash[i] != recv_hash[i])
        {
            printf("--Error--Checksums do not match\n");    // Error handling
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


/**
* @brief uds_dgram_server - Send data to a Unix domain datagram server.
*
* @param argc The number of arguments passed to the program
* @param argv The array of arguments passed to the program
* @return Returns 0 on success, -1 on failure.
*/
int uds_dgram_client(int argc, char *argv[])
{
    int sendStream = 0, totalSent = 0;
    char buffer[MAX_BUFFER_SIZE] = {0};
    struct timeval start, end;
    char *serverType = "udsd";
    char *endMsg = "END";
    send_type_to_server(argc, argv, serverType);

    int sock;
    struct sockaddr_un server_addr, client_address;

    // Create sending socket
    if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
    {
        printf("--Error--Failed to create sending socket\n");
        return -1;
    }

    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, UNIX_SERVER_SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // Create receiving socket
    memset(&client_address, 0, sizeof(struct sockaddr_un));
    client_address.sun_family = AF_UNIX;
    strncpy(client_address.sun_path, UNIX_CLIENT_SOCKET_PATH, sizeof(client_address.sun_path) - 1);
    remove(client_address.sun_path);

    printf("Client started\n");

    // Generate data
    char *data = generate_rand_str(MAX_DATA_SIZE);

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
        printf("--Error--send() failed\n");
        return -1;
    }

    // Send data
    int i = 0;
    gettimeofday(&start, 0);
    while (totalSent < strlen(data))
    {
        int bytes_to_send = (MAX_BUFFER_SIZE < strlen(data) - totalSent) ? MAX_BUFFER_SIZE : strlen(data) - totalSent;
        memcpy(buffer, data + totalSent, bytes_to_send);

        sendStream = sendto(sock, buffer, bytes_to_send, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (sendStream == -1)
        {
            printf("--Error--send() failed\n");
            return -1;
        }

        totalSent += sendStream;
        if (i % 200 == 0 || bytes_to_send < MAX_BUFFER_SIZE)
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
    unlink(UNIX_CLIENT_SOCKET_PATH);
    return 0;
}


/**
* @brief uds_dgram_server - Starts a Unix domain socket datagram server and receives data from clients
* 
* @param argc - The number of arguments passed to the function
* @param argv - An array of strings containing the arguments passed to the function
* @return Returns 0 on success, -1 on failure
*/
int uds_dgram_server(int argc, char *argv[])
{
    int server_fd;
    struct sockaddr_un server_addr, client_addr;
    socklen_t clientAddressLen;
    int bytes = 0, countbytes = 0;
    char buffer[MAX_BUFFER_SIZE] = {0};
    char decoded[MAX_BUFFER_SIZE];
    char *totalData = malloc(MAX_DATA_SIZE);
    struct timeval start, end;

    // Create server socket
    if ((server_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
    {
        printf("--Error--Failed to create server socket\n");
        return -1;
    }

    remove(UNIX_SERVER_SOCKET_PATH);

    // Initialize server address
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, UNIX_SERVER_SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // Bind server socket to address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) == -1)
    {
        printf("--Error--Failed to bind server socket to address\n");
        return -1;
    }

    // Receive checksum
    char hash_str[SHA_DIGEST_LENGTH * 2 + 1];
    bytes = recvfrom(server_fd, hash_str, sizeof(hash_str), 0, (struct sockaddr *)&client_addr, &clientAddressLen);
    if (bytes < 0)
    {
        printf("--Error--recv failed. Sender inactive.\n");
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
            printf("--Error--recv failed. Sender inactive.\n");
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
            printf("--Error--Checksums do not match\n");
            break;
        }
    }

    printf("uds_dgram,%lu\n", milliseconds);

    close(server_fd);
    free(totalData);
    unlink(UNIX_SERVER_SOCKET_PATH);

    return 0;
}


/**
* @brief mmap_client - Maps a file into shared memory and calculates its checksum.
*
* @param argc the number of arguments passed to the program
* @param argv an array of strings containing the arguments passed to the program
* @return Returns 0 on success, -1 on failure.
*/
int mmap_client(int argc, char *argv[])
{
    char *serverType = "mmap";

    // Generate file
    char *data = generate_rand_str(MAX_DATA_SIZE);
    int dataLen = strlen(data);

    FILE *filePtr = fopen(argv[6], "w");
    if (filePtr == NULL)
    {
        printf("--Error-- opening file!\n");
        return -1;
    }
    fprintf(filePtr, "%s", data);
    fclose(filePtr);

    int fd = open(argv[6], O_RDONLY);
    if (fd == -1)
    {
        printf("--Error--open() failed\n");
        return -1;
    }

    void *fileAddr = mmap(NULL, dataLen, PROT_READ, MAP_PRIVATE, fd, 0);
    if (fileAddr == MAP_FAILED)
    {
        printf("--Error--mmap() failed\n");
        return -1;
    }
    close(fd);

    // Calculate and save checksum
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)data, strlen(data), hash);
    free(data);

    int shmFd = shm_open(SHM_FILE_PATH, O_CREAT | O_RDWR, 0666);
    int shmFdName = shm_open(SHM_FILE_NAME, O_CREAT | O_RDWR, 0666);
    int shmFdChecksum = shm_open(SHM_FILE_CS_NAME, O_CREAT | O_RDWR, 0666);
    if (shmFd == -1 || shmFdName == -1 || shmFdChecksum == -1)
    {
        perror("--Error--shm_open() failed\n");
        return -1;
    }

    int res = ftruncate(shmFd, dataLen);
    int res2 = ftruncate(shmFdName, strlen(argv[6]));
    int res3 = ftruncate(shmFdChecksum, sizeof(hash));
    if (res == -1 || res2 == -1 || res3 == -1)
    {
        printf("--Error--ftruncate() failed\n");
        return -1;
    }

    void *shmAddr = mmap(NULL, dataLen, PROT_WRITE, MAP_SHARED, shmFd, 0);
    void *shmNameAddr = mmap(NULL, strlen(argv[6]), PROT_WRITE, MAP_SHARED, shmFdName, 0);
    void *shmChecksumAddr = mmap(NULL, sizeof(hash), PROT_WRITE, MAP_SHARED, shmFdChecksum, 0);
    if (shmAddr == MAP_FAILED || shmNameAddr == MAP_FAILED || shmChecksumAddr == MAP_FAILED)
    {
        printf("--Error--mmap() failed\n");
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


/**
* @brief mmap_server - Retrieves shared memory object and checksum, copies data from shared memory,
*                       calculates the checksum and compares it with the checksum received, and removes the file associated with shared memory.
* 
* @param argc: integer value representing the number of arguments passed to the function.
* @param argv: array of pointers to characters representing the arguments passed to the function.
* @return: 0 on success, -1 on failure.
*/
int mmap_server(int argc, char *argv[])
{
    // Retrieve shared memory object
    struct timeval start, end;
    gettimeofday(&start, NULL);

    int shmFd = shm_open(SHM_FILE_PATH, O_RDONLY, 0666);
    if (shmFd == -1)
    {
        perror("--Error--shm_open() failed\n");
        return -1;
    }

    struct stat shmInfo;
    if (fstat(shmFd, &shmInfo) == -1)
    {
        printf("--Error--fstat() failed\n");
        return -1;
    }

    int shmSize = shmInfo.st_size;
    void *shmAddr = mmap(NULL, shmSize, PROT_READ, MAP_SHARED, shmFd, 0);
    close(shmFd);

    if (shmAddr == MAP_FAILED)
    {
        printf("--Error--mmap() failed\n");
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
    int shmChecksumFd = shm_open(SHM_FILE_CS_NAME, O_RDONLY, 0666);
    if (shmChecksumFd == -1)
    {
        perror("--Error--shm_open() failed\n");
        return -1;
    }

    struct stat checksumInfo;
    if (fstat(shmChecksumFd, &checksumInfo) == -1)
    {
        printf("--Error--fstat() failed\n");
        return -1;
    }

    int checksumSize = checksumInfo.st_size;
    void *checksumAddr = mmap(NULL, checksumSize, PROT_READ, MAP_SHARED, shmChecksumFd, 0);

    if (checksumAddr == MAP_FAILED)
    {
        printf("--Error--mmap() failed\n");
        return -1;
    }

    close(shmChecksumFd);

    unsigned char calculatedHash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)receivedData, strlen(receivedData), calculatedHash);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        if (calculatedHash[i] != ((unsigned char *)checksumAddr)[i])
        {
            printf("--Error--Checksums do not match\n");
            break;
        }
    }

    shm_unlink(SHM_FILE_PATH);
    shm_unlink(SHM_FILE_CS_NAME);
    free(receivedData);

    unsigned long milliseconds = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
    printf("mmap,%lu\n", milliseconds);

    munmap(shmAddr, shmSize);

    // Remove file associated with shared memory
    int shmNameFd = shm_open(SHM_FILE_NAME, O_RDONLY, 0666);
    if (shmNameFd == -1)
    {
        perror("--Error--shm_open() failed\n");
        return -1;
    }

    struct stat nameInfo;
    if (fstat(shmNameFd, &nameInfo) == -1)
    {
        printf("--Error--fstat() failed\n");
        return -1;
    }

    off_t nameSize = nameInfo.st_size;
    void *nameAddr = mmap(NULL, nameSize, PROT_READ, MAP_SHARED, shmNameFd, 0);

    if (nameAddr == MAP_FAILED)
    {
        printf("--Error--mmap() failed\n");
        return -1;
    }

    close(shmNameFd);

    int status = remove((char *)nameAddr);
    if (status != 0)
    {
        printf("--Error--Unable to delete the file\n");
    }

    munmap(nameAddr, nameSize);

    if (shm_unlink(SHM_FILE_NAME) == -1)
    {
        printf("--Error--shm_unlink() failed\n");
        return -1;
    }

    return 0;
}


/**
 * @brief pipe_client - Sends data to a server through a named pipe and calculates and saves checksum into shared memory.
 * 
 * @param argc The number of arguments in the argv array.
 * @param argv An array of strings containing the arguments.
 *             argv[6] is the path to the file to be sent to the server.
 * @return int Returns 0 on success, -1 on failure.
 */
int pipe_client(int argc, char *argv[])
{
    int pipe_fd;
    char buffer[MAX_TCP_BUFFER_SIZE];
    int bytes_read;
    char *data = generate_rand_str(MAX_DATA_SIZE);

    // Calculate and save checksum into shared memory
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)data, strlen(data), hash);

    int shm_fd_checksum = shm_open(SHM_FILE_CS_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd_checksum == -1)
    {
        perror("--Error--shm_open() failed\n");
        return -1;
    }

    int res = ftruncate(shm_fd_checksum, sizeof(hash));
    if (res == -1)
    {
        printf("--Error--ftruncate() failed\n");
        return -1;
    }

    void *shm_checksum_addr = mmap(NULL, sizeof(hash), PROT_WRITE, MAP_SHARED, shm_fd_checksum, 0);
    if (shm_checksum_addr == MAP_FAILED)
    {
        printf("--Error--mmap() failed\n");
        return -1;
    }
    memcpy(shm_checksum_addr, &hash, sizeof(hash));
    munmap(shm_checksum_addr, sizeof(hash));
    close(shm_fd_checksum);

    // Send type to server
    send_type_to_server(argc, argv, "pipe");

    // Open the named pipe for writing
    pipe_fd = open(FIFO_PATH, O_WRONLY);
    if (pipe_fd < 0)
    {
        perror("--Error--Could not open named pipe\n");
        exit(1);
    }

    // Write data to the named pipe
    FILE *file_write = fopen(argv[6], "w");
    if (file_write == NULL)
    {
        printf("--Error--opening file!\n");
        return -1;
    }
    fprintf(file_write, "%s", data);
    fclose(file_write);

    FILE *file_read = fopen(argv[6], "r");
    if (file_read == NULL)
    {
        printf("--Error--opening file!\n");
        return -1;
    }
    while ((bytes_read = fread(buffer, 1, MAX_TCP_BUFFER_SIZE, file_read)) > 0)
    {
        if (write(pipe_fd, buffer, bytes_read) < 0)
        {
            fprintf(stderr, "--Error--ould not write to named pipe\n");
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


/**
* @brief pipe_server - The pipe_server function sets up a named pipe and reads data from it. The function then calculates the SHA-1 hash of the received data and compares it with the hash value obtained from shared memory. Finally, the function calculates and prints the time taken to receive data from the named pipe.
* 
* @param argc An integer representing the number of command-line arguments passed to the program.
* @param argv An array of strings representing the command-line arguments passed to the program.
* @return An integer indicating whether the function executed successfully or not.
*/
int pipe_server(int argc, char *argv[])
{
    int fifoFileDescriptor, countBytes = 0;
    char buf[MAX_TCP_BUFFER_SIZE], *totalData = malloc(MAX_DATA_SIZE);
    struct timeval startTime, endTime;

    mkfifo(FIFO_PATH, 0666);
    fifoFileDescriptor = open(FIFO_PATH, O_RDONLY);
    if (fifoFileDescriptor < 0)
    {
        fprintf(stderr, "--Error--Could not open named pipe\n");
        exit(1);
    }

    int bytesRead = 0;

    // Get checksum from shared memory
    int sharedMemoryChecksumFd = shm_open(SHM_FILE_CS_NAME, O_RDONLY, 0666);
    if (sharedMemoryChecksumFd == -1)
    {
        perror("--Error--shm_open() failed\n");
        return -1;
    }
    struct stat sharedMemoryChecksumStat;
    if (fstat(sharedMemoryChecksumFd, &sharedMemoryChecksumStat) == -1)
    {
        printf("--Error--fstat() failed\n");
        return -1;
    }
    int checksumLength = sharedMemoryChecksumStat.st_size;
    void *checksumAddress = mmap(NULL, checksumLength, PROT_READ, MAP_SHARED, sharedMemoryChecksumFd, 0);
    if (checksumAddress == MAP_FAILED)
    {
        printf("--Error--mmap() failed\n");
        return -1;
    }
    close(sharedMemoryChecksumFd);

    // Read from FIFO
    gettimeofday(&startTime, 0);
    while ((bytesRead = read(fifoFileDescriptor, buf, MAX_TCP_BUFFER_SIZE)) > 0)
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
            printf("--Error--Checksums Do not match\n");
            break;
        }
    }

    unsigned long milliseconds = (endTime.tv_sec - startTime.tv_sec) * 1000 + (endTime.tv_usec - startTime.tv_usec) / 1000;
    printf("pipe,%lu\n", milliseconds);
    close(fifoFileDescriptor);
    unlink(FIFO_PATH);
    shm_unlink(SHM_FILE_CS_NAME);
    free(totalData);
    return 0;
}


/**
* @brief tcp_server - Establishes a TCP server and receives data from the client. Calculates the checksum of the received data and compares it with the checksum received from the client.
* 
* @param argc The number of command-line arguments
* @param argv An array of strings containing the command-line arguments
* @param type The address type (IPV4 or IPV6)
* @return 0 on success, -1 on failure
*/
int tcp_server(int argc, char *argv[], enum addr type)
{
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddress, clientAddress;
    struct sockaddr_in6 serverAddress6, clientAddress6;
    socklen_t clientAddressLen;
    int option = 1, bytes = -1, totalBytes = 0;
    char receiveBuffer[MAX_TCP_BUFFER_SIZE] = {0};
    char *totalData = malloc(MAX_DATA_SIZE);
    struct timeval startTime, endTime;

    if (type == IPV4)
    {
        // Create server socket
        if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            printf("\n--Error--Socket creation error\n");
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
            printf("\n--Error--Setsockopt error\n");
            return -1;
        }

        // Bind socket to address
        if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        {
            perror("\n--Error--TCP bind failed\n");
            return -1;
        }
    }
    else if (type == IPV6)
    {
        // Create server socket
        if ((serverSocket = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
        {
            printf("\n--Error--Could not creat Socket.\n");
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
            printf("\n--Error--Setsockopt error\n");
            return -1;
        }

        // Bind socket to address
        if (bind(serverSocket, (struct sockaddr *)&serverAddress6, sizeof(serverAddress6)) < 0)
        {
            printf("\n--Error--TCP bind failed\n");
            return -1;
        }
    }
    else
    {
        printf("--Error--Invalid address type\n");
        return -1;
    }

    // Listen for incoming connections
    if (listen(serverSocket, 3) < 0)
    {
        printf("--Error--Listen error\n");
        return -1;
    }
    if (type == IPV4)
    {
        if ((clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLen)) < 0)
        {
            printf("--Error--Accept error\n");
            return -1;
        }
    }
    else if (type == IPV6)
    {
        if ((clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress6, &clientAddressLen)) < 0)
        {
            printf("--Error--Accept error\n");
            return -1;
        }
    }

    // Receive checksum
    char receivedHashStr[SHA_DIGEST_LENGTH * 2 + 1];
    bytes = recv(clientSocket, receivedHashStr, sizeof(receivedHashStr), 0);
    if (bytes < 0)
    {
        printf("--Error--Recv failed. Sender inactive.\n");
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
            printf("--Error--Recv failed. Sender inactive.\n");
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
            printf("--Error--Checksums does not match\n");
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


/**
 * @brief tcp_client - Establishes a TCP connection to a server and sends data.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line arguments, including the server address and port.
 * @param type The address family (IPV4 or IPV6) to use.
 * @return 0 on success, or -1 on failure.
 */
int tcp_client(int argc, char *argv[], enum addr type)
{
    char *serverType;
    if (type == IPV4)
    {
        serverType = "tcp4";
    }
    else
    {
        serverType = "tcp6";
    }
    send_type_to_server(argc, argv, serverType);

    int socket_fd = 0;
    int bytes_sent = 0, total_bytes_sent = 0;
    char buffer[MAX_TCP_BUFFER_SIZE] = {0};
    struct sockaddr_in server_addr_ipv4;
    struct sockaddr_in6 server_addr_ipv6;
    struct timeval start_time, end_time;

    if (type == IPV4)
    {
        // Create socket
        if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            printf("\n--Error--Socket creation error\n");
            return -1;
        }

        memset(&server_addr_ipv4, 0, sizeof(server_addr_ipv4));

        // Set socket address
        server_addr_ipv4.sin_family = AF_INET;
        server_addr_ipv4.sin_port = htons(atoi(argv[3]));

        // Convert IPv4 and store in sin_addr
        if (inet_pton(AF_INET, argv[2], &server_addr_ipv4.sin_addr) <= 0)
        {
            printf("\n--Error--Invalid address/Address not supported\n");
            return -1;
        }

        // Connect to server socket
        if (connect(socket_fd, (struct sockaddr *)&server_addr_ipv4, sizeof(server_addr_ipv4)) < 0)
        {
            perror("\n--Error--Connection failed\n");
            return -1;
        }
    }
    else if (type == IPV6)
    {
        // Create socket
        if ((socket_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
        {
            printf("\n--Error--Socket creation error\n");
            return -1;
        }

        memset(&server_addr_ipv6, '0', sizeof(server_addr_ipv6));

        // Set socket address
        server_addr_ipv6.sin6_family = AF_INET6;
        server_addr_ipv6.sin6_port = htons(atoi(argv[3]));

        // Convert IPv6 and store in sin6_addr
        if (inet_pton(AF_INET6, argv[2], &server_addr_ipv6.sin6_addr) <= 0)
        {
            printf("\n--Error--Invalid address/Address not supported\n");
            return -1;
        }

        // Connect to server socket
        if (connect(socket_fd, (struct sockaddr *)&server_addr_ipv6, sizeof(server_addr_ipv6)) < 0)
        {
            printf("\n--Error--Connection failed\n");
            return -1;
        }
    }
    else
    {
        printf("--Error--Invalid address type\n");
        return -1;
    }

    printf("Server connection Established\n");

    // Generate data
    char *data = generate_rand_str(MAX_DATA_SIZE);

    // Calculate and send checksum
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)data, strlen(data), hash);
    char hash_string[SHA_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        sprintf(&hash_string[i * 2], "%02x", hash[i]);
    }
    hash_string[SHA_DIGEST_LENGTH * 2] = '\0';
    bytes_sent = send(socket_fd, hash_string, strlen(hash_string), 0);
    if (-1 == bytes_sent)
    {
        printf("--Error--send() failed");
        close(socket_fd);
        exit(1);
    }

    gettimeofday(&start_time, 0);
    while (total_bytes_sent < strlen(data))
    {
        int bytes_to_send = (MAX_TCP_BUFFER_SIZE < strlen(data) - total_bytes_sent) ? MAX_TCP_BUFFER_SIZE : strlen(data) - total_bytes_sent;
        memcpy(buffer, data + total_bytes_sent, bytes_to_send);
        bytes_sent = send(socket_fd, buffer, bytes_to_send, 0);
        if (-1 == bytes_sent)
        {
            printf("--Error--send() failed");
            exit(1);
        }

        total_bytes_sent += bytes_sent;
        // printf("Bytes sent: %d\n", total_bytes_sent);
        // printf("Bytes to send: %d\n", bytes_to_send);
        bytes_sent = 0;
        memset(buffer, 0, sizeof(buffer));
    }
    gettimeofday(&end_time, 0);
    unsigned long milliseconds = (end_time.tv_sec - start_time.tv_sec) * 1000 + (end_time.tv_usec - start_time.tv_usec) / 1000;
    printf("Total bytes sent: %d\nTime elapsed: %lu milliseconds\n", total_bytes_sent, milliseconds);
    // Close socket
    close(socket_fd);
    free(data);
    return 0;
}


/**
* @brief server - A function to create a server that listens to incoming connections,
*                 accepts and handles them using a select loop and allows communication
*                 between the server and the connected client using TCP/IP sockets.

* @param argc an integer argument count of the command-line arguments
* @param argv an array of character pointers listing all the command-line arguments
* @return an integer value indicating the success (0) or failure (-1) of the server
*/
int server(int argc, char *argv[])
{
    int server_socket, client_socket;
    struct sockaddr_in server_address;
    int option = 1;
    char buffer[MAX_BUFFER_SIZE] = {0};
    fd_set read_fds;

    // Create socket file descriptor
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("--Error--socket failed");
        exit(EXIT_FAILURE);
    }

    // Attach socket to the port
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | 15, &option, sizeof(option)))
    {
        perror("--Error--setsockopt");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(atoi(argv[2]));

    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        perror("--Error--binding failure");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 3) < 0)
    {
        perror("--Error--listen");
        exit(EXIT_FAILURE);
    }
    printf("Server is listening on port %s\n", argv[2]);

    // Accept and handle incoming connections
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);
    memset(&client_address, 0, sizeof(client_address));
    client_address_len = sizeof(client_address);
    client_socket = accept(server_socket, (struct sockaddr *)&client_address, &client_address_len);
    if (client_socket == -1)
    {
        printf("--Error--listen failed with error code : %d", errno);
        close(server_socket);
        close(client_socket);
        return -1;
    }
    printf("Client connected: %s:%d\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));

    while (1)
    {
        FD_ZERO(&read_fds);
        FD_SET(server_socket, &read_fds);
        FD_SET(client_socket, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        int max_fd = (server_socket > client_socket) ? server_socket : client_socket;
        int result = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (result == -1)
        {
            perror("--Error-- in select");
            exit(EXIT_FAILURE);
        }
        else if (result == 0)
        {
            continue;
        }
        else
        {
            if (FD_ISSET(STDIN_FILENO, &read_fds))
            {
                if (fgets(buffer, MAX_BUFFER_SIZE, stdin) == NULL)
                {
                    perror("--Error-- Can not read input");
                    exit(EXIT_FAILURE);
                }
                int bytes_sent = send(client_socket, buffer, strlen(buffer), 0);
                if (bytes_sent == -1)
                {
                    perror("--Error--error Can not send message");
                    exit(EXIT_FAILURE);
                }
                /*
                else
                {
                    printf("sent message to client: %s\n", message);
                }
                */
            }

            if (FD_ISSET(client_socket, &read_fds))
            {
                int bytes_received = read(client_socket, buffer, MAX_BUFFER_SIZE);
                if (bytes_received == -1)
                {
                    perror("--Error--Can not receive message");
                    exit(EXIT_FAILURE);
                }
                else if (bytes_received == 0)
                {
                    // client closed the connection
                    printf("Client disconnected\n");
                    close(client_socket);
                    FD_CLR(client_socket, &read_fds);
                    client_socket = accept(server_socket, (struct sockaddr *)&client_address, &client_address_len);
                    if (client_socket == -1)
                    {
                        printf("--Error--Listening Failure with error code : %d", errno);
                        close(server_socket);
                        close(client_socket);
                        return -1;
                    }
                    printf("Client connected: %s:%d\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));
                }
                else
                {
                    buffer[bytes_received] = '\0';
                    printf("Client message: %s", buffer);
                }
            }
        }
    }
    return 0;
}


/**
* @brief uds_stream_client - Sends a stream of data to a Unix domain socket server using the "udss" protocol.

* @param argc The number of arguments passed to the program.
* @param argv The array of arguments passed to the program.
* @return Returns 0 on success, -1 on failure.
*/
int uds_stream_client(int argc, char *argv[])
{
    char *serverType = "udss";
    send_type_to_server(argc, argv, serverType);

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1)
    {
        printf("--Error--Failed to create client socket\n");
        return -1;
    }

    struct sockaddr_un server_address = {0};
    server_address.sun_family = AF_UNIX;
    strncpy(server_address.sun_path, UNIX_SOCKET_PATH, sizeof(server_address.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&server_address, sizeof(struct sockaddr_un)) == -1)
    {
        perror("--Error--Failed to connect to server\n");
        return -1;
    }

    printf("Server Connection Established\n");

    char *data = generate_rand_str(MAX_DATA_SIZE);
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)data, strlen(data), hash);

    char hash_str[SHA_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }
    hash_str[SHA_DIGEST_LENGTH * 2] = '\0';

    if (send(sock, hash_str, strlen(hash_str), 0) == -1)
    {
        printf("--Error--send() Failure");
        close(sock);
        return -1;
    }

    struct timeval start, end;
    gettimeofday(&start, 0);

    int totalSent = 0;
    char buffer[MAX_TCP_BUFFER_SIZE];
    int sendStream = 0;

    while (totalSent < strlen(data))
    {
        int bytes_to_read = MAX_TCP_BUFFER_SIZE < strlen(data) - totalSent ? MAX_TCP_BUFFER_SIZE : strlen(data) - totalSent;
        memcpy(buffer, data + totalSent, bytes_to_read);

        sendStream = send(sock, buffer, bytes_to_read, 0);
        if (sendStream == -1)
        {
            printf("--Error--send() Failure");
            close(sock);
            return -1;
        }

        totalSent += sendStream;
        bzero(buffer, sizeof(buffer));
    }

    gettimeofday(&end, 0);
    unsigned long milliseconds = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;

    printf("Total bytes sent: %d\nTime elapsed: %lu milliseconds\n", totalSent, milliseconds);

    close(sock);
    free(data);
    return 0;
}


/**
* @brief uds_stream_server - Create Unix domain socket server and receive data

* @param argc: the number of command-line arguments
* @param argv: an array of strings containing the command-line arguments
* @return: 0 on success, -1 on failure
*/
int uds_stream_server(int argc, char *argv[])
{
    int server_fd, client_fd;
    struct sockaddr_un address;
    char buffer[MAX_TCP_BUFFER_SIZE];
    char *totalData = malloc(MAX_DATA_SIZE);
    struct timeval start, end;
    int bytes = 0, countbytes = 0;

    // Create server socket
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        printf("--Error--Failed to create server socket\n");
        return -1;
    }

    remove(UNIX_SOCKET_PATH);
    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, UNIX_SOCKET_PATH, sizeof(address.sun_path) - 1);

    // Bind socket to address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) == -1)
    {
        printf("--Error--Failed to bind server socket to address\n");
        return -1;
    }

    // Listen for incoming connections
    if (listen(server_fd, 5) == -1)
    {
        printf("--Error--Incoming connection acception Failure\n");
        return -1;
    }

    // Accept incoming connections
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd == -1)
    {
        printf("--Error--Incoming connection acception Failure\n");
        return -1;
    }

    // Receive checksum
    char hash_str[SHA_DIGEST_LENGTH * 2 + 1];
    bytes = recv(client_fd, hash_str, sizeof(hash_str), 0);
    if (bytes < 0)
    {
        printf("--Error--recv failed.\n");
        close(server_fd);
        close(client_fd);
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
        bytes = recv(client_fd, buffer, sizeof(buffer), 0);
        if (bytes < 0)
        {
            printf("--Error--recv failed.\n");
            close(server_fd);
            close(client_fd);
            return -1;
        }
        else if (countbytes && bytes == 0)
        {
            break;
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
            printf("--Error--Checksums Does Not Match!\n");
            break;
        }
    }

    printf("uds_stream,%lu\n", milliseconds);

    close(client_fd);
    close(server_fd);
    free(totalData);
    unlink(UNIX_SOCKET_PATH);
    return 0;
}


/**
* @brief brief getServerType - Function for retrieving the type of a server.
* @param argc Number of arguments passed to the function
* @param argv Array of arguments passed to the function
* @return char* A string indicating the type of server based on the data received through the connection
*/
char *getServerType(int argc, char *argv[])
{
    int server_fd = -1, new_socket = -1;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char *buffer = malloc(20);

    // Create server socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("s--Error--Socket Failure");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("--Error--Socket not set");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Bind socket to port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(atoi(argv[2]));

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("--Error--getServer bind Failure");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0)
    {
        perror("--Error--listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Accept incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
    {
        perror("--Error--accept");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    int bytes = recv(new_socket, buffer, sizeof(buffer), 0);
    if (bytes < 0)
    {
        perror("--Error--recv");
        close(server_fd);
        close(new_socket);
        exit(EXIT_FAILURE);
    }

    close(server_fd);
    close(new_socket);
    return buffer;
}


/**
 * @brief send_type_to_server - Sends a type string to a server.
 * 
 * @param argc The number of command line arguments.
 * @param argv An array of command line arguments.
 *             The 4th argument is expected to be the port number of the server.
 * @param type The type string to be sent to the server.
 * @return 0 if the type was sent successfully, -1 otherwise.
 */
int send_type_to_server(int argc, char *argv[], char *type)
{
    int sock = 0;
    struct sockaddr_in serv_addr;
    char *bufferser = type;

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n--Error--Socket creation error \n");
        return -1;
    }
    memset(&serv_addr, '0', sizeof(serv_addr));

    // Set server address and port
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[3]));

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
    {
        printf("\n--Error--Invalid address \n");
        close(sock);
        return -1;
    }
    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("\n--Error--Connection Failed\n");
        close(sock);
        return -1;
    }
    send(sock, bufferser, strlen(bufferser), 0);
    close(sock);
    usleep(50000);
    return 0;
}


/**
* @brief generate_rand_str - Generates a random string of the given length.
* @param length the length of the string to generate.
* @return a pointer to the generated string.
*/
char *generate_rand_str(int length)
{
    char *string = malloc(length + 1);
    if (!string)
    {
        return NULL;
    }

    for (int i = 0; i < length; i++)
    {
        int num = rand() % 26;
        string[i] = 'a' + num;
    }
    string[length] = '\0';
    return string;
}


/**
* @brief min - Returns the minimum of two integers.
* @param a An integer value.
* @param b An integer value.
* @return The minimum value of a and b.
*/
int min(int a, int b)
{
    return (a < b) ? a : b;
}