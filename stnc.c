#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printUsage();
void handleClient(int argc, char *argv[]);
void handleServer(int argc, char *argv[]);
int init_client(int argc, char *argv[]);

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
                udp_client(argc, argv);
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
                udp_client(argc, argv);
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