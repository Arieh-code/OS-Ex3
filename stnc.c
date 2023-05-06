#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include "stnc.h"

#define MAX_MESSAGE_LEN 1024
#define BACKLOG 5

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sockfd, newsockfd, portno;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    char buffer[MAX_MESSAGE_LEN];
    char *ip;

    if (argc < 3)
    {
        fprintf(stderr, "Usage:\nClient: %s -c IP PORT\nServer: %s -s PORT\n", argv[0], argv[0]);
        return 1;
    }

    // Parse command-line arguments
    if (strcmp(argv[1], "-c") == 0)
    {
        ip = argv[2];
        portno = atoi(argv[3]);
    }
    else if (strcmp(argv[1], "-s") == 0)
    {
        ip = NULL;
        portno = atoi(argv[2]);
    }
    else
    {
        fprintf(stderr, "Invalid option\n");
        return 1;
    }

    if (ip != NULL)
    {
        // Create socket (Client)
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
            error("Error opening socket");
        }

        // Set up server address structure (Client)
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(portno);
        if (inet_pton(AF_INET, ip, &(serv_addr.sin_addr)) <= 0)
        {
            error("Invalid IP address");
        }

        // Connect to the server
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            error("Error connecting to the server");
        }

        printf("Connected to the server.\n");

        struct pollfd fds[2];
        fds[0].fd = STDIN_FILENO; // Keyboard input
        fds[0].events = POLLIN;
        fds[1].fd = sockfd; // Socket
        fds[1].events = POLLIN;

        while (1)
        {
            if (poll(fds, 2, -1) < 0)
            {
                error("Error in poll");
            }

            if (fds[0].revents & POLLIN)
            {
                // Keyboard input is available
                memset(buffer, 0, sizeof(buffer));
                fgets(buffer, sizeof(buffer), stdin);
                send(sockfd, buffer, strlen(buffer), 0);
            }

            if (fds[1].revents & POLLIN)
            {
                // Socket data is available
                memset(buffer, 0, sizeof(buffer));
                int recv_bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
                if (recv_bytes <= 0)
                {
                    // Server has closed the connection
                    printf("Server disconnected\n");
                    break;
                }
                else
                {
                    printf("Server: %s", buffer);
                }
            }
        }

        // Close the socket
        close(sockfd);
    }
    else
    {
        // Create socket (Server)
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
            error("Error opening socket");
        }

        // Set up server address structure (Server)
        // Set up server address structure (Server)
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(portno);

        // Bind the socket to the server address
        if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            error("Error binding socket");
        }

        // Listen for incoming connections
        if (listen(sockfd, BACKLOG) < 0)
        {
            error("Error listening for connections");
        }

        printf("Waiting for incoming connections...\n");

        while (1)
        {
            clilen = sizeof(cli_addr);
            newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
            if (newsockfd < 0)
            {
                error("Error accepting connection");
            }

            printf("Client connected\n");

            struct pollfd fds[2];
            fds[0].fd = STDIN_FILENO; // Keyboard input
            fds[0].events = POLLIN;
            fds[1].fd = newsockfd; // Socket
            fds[1].events = POLLIN;

            while (1)
            {
                if (poll(fds, 2, -1) < 0)
                {
                    error("Error in poll");
                }

                if (fds[0].revents & POLLIN)
                {
                    // Keyboard input is available
                    memset(buffer, 0, sizeof(buffer));
                    fgets(buffer, sizeof(buffer), stdin);
                    send(newsockfd, buffer, strlen(buffer), 0);
                }

                if (fds[1].revents & POLLIN)
                {
                    // Socket data is available
                    memset(buffer, 0, sizeof(buffer));
                    int recv_bytes = recv(newsockfd, buffer, sizeof(buffer) - 1, 0);
                    if (recv_bytes <= 0)
                    {
                        // Client has closed the connection
                        printf("Client disconnected\n");
                        break;
                    }
                    else
                    {
                        printf("Client: %s", buffer);
                    }
                }
            }

            // Close the connection
            close(newsockfd);
        }

        // Close the socket
        close(sockfd);
    }

    return 0;
}
