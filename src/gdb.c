#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include "defs.h"

const astro_err_t *astro_host_gdb_server(astro_t *astro) {
    const astro_err_t *astro_err;
    int sockfd;

    if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
        astro_err = astro_perror(astro, "socket() for gdb server");
        goto failure;
    }

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof addr);
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(ASTRO_GDB_PORT_NUMBER);
    memcpy(&addr.sin6_addr, &in6addr_loopback, sizeof addr.sin6_addr);

    if (bind(sockfd, (struct sockaddr *) &addr, sizeof addr) == -1) {
        astro_err = astro_perror(astro, "bind() for gdb server");
        goto failure;
    }

    return NULL;

    failure:
    return astro_err;
}
