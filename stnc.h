#ifndef STNC_H
#define STNC_H

#include <poll.h>

void error(const char *msg);
void handle_communication(int sockfd);

#endif
