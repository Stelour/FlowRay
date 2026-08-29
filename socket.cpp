#include "main.h"
#include "socket.h"

static int send_req(int fd) {
    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK
    };

    DiagRequest req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.req.sdiag_family = AF_INET;
    req.req.sdiag_protocol = IPPROTO_TCP;
    req.req.idiag_states = 0xFFFFFFFF;

    struct iovec iov = {
        .iov_base = &req,
        .iov_len = sizeof(req)
    };

    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    for (;;) {
        if (sendmsg(fd, &msg, 0) < 0) {
            if (errno == EINTR)
                continue;

            std::cerr << "ERROR: sendmsg" << std::endl;
            return 2;
        }
        return 0;
    }
}

status_msg socket_req() {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        std::perror("ERROR: failed to create sock_diag socket");
        return status_msg::error;
    }
    std::cout << "sock_diag fd: " << fd << '\n';
    if (send_req(fd) > 0) {
        close(fd);
        return status_msg::error;
    }
    std::cout << "request send" << std::endl;
    close(fd);
    return status_msg::success;
}