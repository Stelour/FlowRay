#include "main.h"
#include "socket.h"

static int send_req(int fd) {
    // send to Linux kernel.
    sockaddr_nl kernel_addr{};
    kernel_addr.nl_family = AF_NETLINK;
    kernel_addr.nl_pid = 0;
    kernel_addr.nl_groups = 0;

    // sock_diag msg
    DiagRequest req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.req.sdiag_family = AF_INET;
    req.req.sdiag_protocol = IPPROTO_TCP;
    req.req.idiag_states = 0xFFFFFFFF;

    // buffer of msg
    iovec iov{};
    iov.iov_base = &req;
    iov.iov_len = sizeof(req);

    // desc
    msghdr msg{};
    msg.msg_name = &kernel_addr;
    msg.msg_namelen = sizeof(kernel_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    for (;;) {
        if (sendmsg(fd, &msg, 0) < 0) {
            if (errno == EINTR)
                continue;

            std::cerr << "ERROR: sendmsg" << std::endl;
            return 1;
        }
        return 0;
    }
}

// static int receive_response(int fd) {
//     alignas(nlmsghdr) char buffer[8192]{};
//     sockaddr_nl nladdr{};
//     iovec iov{
//         .iov_base = buffer,
//         .iov_len = sizeof(buffer)
//     };
//     msghdr msg{
//         .msg_name = &nladdr,
//         .msg_namelen = sizeof(nladdr),
//         .msg_iov = &iov,
//         .msg_iovlen = 1
//     };
//     int flags = 0;
// }

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
    // if (receive_response(fd) > 0) {
    //     close(fd);
    //     return status_msg::error;
    // }
    close(fd);
    return status_msg::success;
}