#include "output.h"

#include <iostream>
#include <netinet/in.h>
#include <string>
#include <iomanip>

static std::string state_to_string(std::uint8_t state) {
    switch (state) {
        case 1: return "ESTABLISHED";
        case 2: return "SYN_SENT";
        case 3: return "SYN_RECV";
        case 4: return "FIN_WAIT1";
        case 5: return "FIN_WAIT2";
        case 6: return "TIME_WAIT";
        case 7: return "CLOSE";
        case 8: return "CLOSE_WAIT";
        case 9: return "LAST_ACK";
        case 10: return "LISTEN";
        case 11: return "CLOSING";
        case 12: return "NEW_SYN_RECV";
        default: return "UNKNOWN";
    }
}

static std::string protocol_to_string(int protocol) {
    switch (protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default: return "UNKNOWN";
    }
}

static std::string family_to_string(int family) {
    switch (family) {
        case AF_INET: return "IPv4";
        case AF_INET6: return "IPv6";
        default: return "UNKNOWN";
    }
}

void print_process_info(const ProcessInfo& proc_info) {
    std::cout << "PID: " << proc_info.pid << std::endl;
    std::cout << "Process name: " << proc_info.name << std::endl;
    std::cout << std::endl;
    // std::cout << "Socket inodes:" << std::endl;
    // for (const std::uint32_t& s : proc_info.socket_inodes) {
    //     std::cout << s << std::endl;
    // }
}

void print_socket_info(const std::vector<SocketInfo>& sockets, bool detail) {
    std::cout << "Sockets: " << sockets.size() << std::endl << std::endl;

    std::cout << std::left
    << std::setw(11) << "PROTOCOL |"
    << std::setw(10) << "FAMILY |"
    << std::setw(28) << "LOCAL"
    << std::setw(28) << "REMOTE"
    << std::setw(15) << "STATE";
    if (detail) {
        std::cout << std::setw(20) << "PIDS" << std::setw(12) << "INODE";
    }
    std::cout << std::endl << std::endl;

    for (const auto& socket : sockets) {
        std::cout << std::left
        << std::setw(11) << protocol_to_string(socket.protocol)
        << std::setw(10) << family_to_string(socket.family)
        << std::setw(28) << socket.local_ip + ":" + std::to_string(socket.local_port)
        << std::setw(28) << socket.remote_ip + ":" + std::to_string(socket.remote_port);
        if (socket.protocol == IPPROTO_TCP) {
            std::cout << std::setw(15) << state_to_string(socket.state);
        } else {
            std::cout << std::setw(15) << "-";
        }
        if (detail) {
            std::string pids;
            for (const auto pid : socket.pids) {
                if (!pids.empty()) {
                    pids += ',';
                }
                pids += std::to_string(pid);
            }
            std::cout << std::setw(20) << pids << std::setw(12) << socket.inode;
        }
        std::cout << std::endl;
    }
}