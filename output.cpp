#include "output.h"

#include <iostream>
#include <netinet/in.h>
#include <string>

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
    std::cout << "Sockets:" << std::endl;

    for (const auto& socket : sockets) {
        std::cout
        << protocol_to_string(socket.protocol) << '\t'
        << family_to_string(socket.family) << '\t'
        << socket.local_ip << ':' << socket.local_port << " -> "
        << socket.remote_ip << ':' << socket.remote_port;
        if (socket.protocol == IPPROTO_TCP) {
            std::cout << '\t' << state_to_string(socket.state) << std::endl;
        }
        if (detail) {
            std::cout << "\tPID: ";
            for (const auto pid : socket.pids) {
                std::cout << pid << ' ';
            }
            std::cout << std::endl;
            std::cout << "\tinode: " << socket.inode << std::endl;
        }
        std::cout << std::endl;
    }
}