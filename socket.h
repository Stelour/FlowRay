#ifndef FLOWRAY_SOCKET_H
#define FLOWRAY_SOCKET_H

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h> // for IPv4 and IPv6 sockets
#include <netinet/in.h>
#include <unistd.h>
#include <cerrno>
#include <arpa/inet.h>

struct DiagRequest {
    nlmsghdr nlh{};
    inet_diag_req_v2 req{};
};

#endif //FLOWRAY_SOCKET_H
