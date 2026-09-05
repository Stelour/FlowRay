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

static int print_diag(const struct inet_diag_msg *diag, unsigned int size) {
    // diag->idiag_family
    // diag->idiag_state
    // diag->id.idiag_sport
    // diag->id.idiag_dport
    // diag->id.idiag_src
    // diag->id.idiag_dst
    // diag->idiag_uid
    // diag->idiag_inode

    if (size < NLMSG_LENGTH(sizeof(*diag))) {
        std::cerr << "short response" << std::endl;
        return -1;
    }

    if (diag->idiag_family != AF_INET) {
        std::cerr << "unexpected family" << std::endl;
        return -1;
    }

    std::cout << "inode=" << diag->idiag_inode;
    std::cout << " uid=" << diag->idiag_uid;
    std::cout << " state=" << static_cast<unsigned>(diag->idiag_state) << std::endl;

    return 0;
}

static int receive_response(int fd) {
    alignas(nlmsghdr) char buffer[8192]{}; // todo

    sockaddr_nl nladdr{};

    struct iovec iov = {
        .iov_base = buffer,
        .iov_len = sizeof(buffer)
    };

    for (;;) {
        struct msghdr msg = {
            .msg_name = &nladdr,
            .msg_namelen = sizeof(nladdr),
            .msg_iov = &iov,
            .msg_iovlen = 1
        };
        ssize_t ret = recvmsg(fd, &msg, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }

            std::cerr << "recvmsg" << std::endl;
            return -1;
        }

        if (ret == 0) {
            return 0;
        }

        if (nladdr.nl_family != AF_NETLINK) {
            std::cerr << "!AF_NETLINK" << std::endl;
            return -1;
        }

        const struct nlmsghdr *h = (struct nlmsghdr *) buffer;
        if (!NLMSG_OK(h, ret)) {
            std::cerr << "!NLMSG_OK" << std::endl;
            return -1;
        }

        // std::cout
        // << "received bytes: " << ret << '\n'
        // << "sender family: " << nladdr.nl_family << '\n'
        // << "nlmsg_len: " << h->nlmsg_len << '\n'
        // << "nlmsg_type: " << h->nlmsg_type << '\n'
        // << "nlmsg_flags: " << h->nlmsg_flags << '\n';
        // return 0;

        for (; NLMSG_OK(h, ret); h = NLMSG_NEXT(h, ret)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                return 0;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
                    std::cerr << "NLMSG_ERROR\n";
                    return -1;
                }
                const auto *err = static_cast<const nlmsgerr *>(NLMSG_DATA(h));
                errno = -err->error;
                std::perror("NLMSG_ERROR");
                return -1;
            }
            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
                std::cerr << "unexpected type\n";
                return -1;
            }
            if (print_diag(static_cast<const struct inet_diag_msg*>(NLMSG_DATA(h)), h->nlmsg_len)) {
                return -1;
            }
        }

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
    if (receive_response(fd) > 0) {
        close(fd);
        return status_msg::error;
    }
    close(fd);
    return status_msg::success;
}