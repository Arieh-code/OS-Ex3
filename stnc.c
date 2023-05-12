#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        client(argc, argv);
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
