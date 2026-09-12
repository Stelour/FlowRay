#include <netinet/in.h>

#include "main.h"

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

static bool check_pid_is_correct(const std::string& dir_path) {
    return std::filesystem::is_directory(dir_path);
}

static void find_socket_inodes(
    const std::string& dir_path,
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>& socket_inodes,
    std::uint32_t proc_pid) {
    for (const auto& entry : std::filesystem::directory_iterator(dir_path + "/fd")) {
        std::error_code ec;
        std::string cur_fd = std::filesystem::read_symlink(entry.path(), ec);
        if (ec) {
            continue;
        }
        if (cur_fd.starts_with("socket:[")) {
            // socket_inodes.insert(std::stoul(
            //     cur_fd.substr(cur_fd.find('[') + 1, cur_fd.find(']') - cur_fd.find('[') - 1)));
            socket_inodes[
                std::stoul(cur_fd.substr(cur_fd.find('[') + 1, cur_fd.find(']') - cur_fd.find('[') - 1))
                ].push_back(proc_pid);
        }
    }
}

static void print_process_info(const ProcessInfo& proc_info) {
    std::cout << "PID: " << proc_info.pid << std::endl;
    std::cout << "Process name: " << proc_info.name << std::endl;
    std::cout << std::endl;
    // std::cout << "Socket inodes:" << std::endl;
    // for (const std::uint32_t& s : proc_info.socket_inodes) {
    //     std::cout << s << std::endl;
    // }
}

static void print_socket_info(const std::vector<SocketInfo>& sockets, bool detail) {
    std::cout << "Sockets:" << std::endl;

    for (const auto& socket : sockets) {
        std::cout
        << protocol_to_string(socket.protocol) << '\t'
        << family_to_string(socket.family) << '\t'
        << socket.local_ip << ':' << socket.local_port << " -> "
        << socket.remote_ip << ':' << socket.remote_port;
        if (protocol_to_string(socket.protocol) == "TCP") {
            std::cout << '\t' << state_to_string(socket.state) << std::endl;
        } else {
            std::cout << std::endl;
        }
        if (detail) {
            std::cout << "\tPID: ";
            for (const auto pid : socket.pids) {
                std::cout << pid << ' ';
            }
            std::cout << std::endl;
            std::cout << "\tinode: " << socket.inode << std::endl;
        }
    }
}

status_msg start_pid(int pid, bool need_print_about_proc, bool pid_tree, bool pid_detail) {
    std::string str_pid = std::to_string(pid);
    std::string dir_path = "/proc/" + str_pid;
    if (check_pid_is_correct(dir_path) == false) {
        std::cerr << "ERROR: incorrect PID" << std::endl;
        return status_msg::error;
    }

    std::ifstream file_pid_comm(dir_path + "/comm");
    std::string process_name;
    std::getline(file_pid_comm, process_name);

    std::vector<std::uint32_t> procs_pid;
    procs_pid.push_back(pid);
    if (pid_tree == true) {
        push_pid_tree(pid, procs_pid);
    }

    // std::unordered_set<std::uint32_t> socket_inodes = {};
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> socket_inodes;
    for (auto& proc_pid : procs_pid) {
        find_socket_inodes("/proc/" + std::to_string(proc_pid), socket_inodes, proc_pid);
    }

    ProcessInfo proc_info = {pid, process_name, dir_path, socket_inodes};

    // req to socket
    DiagQuery ipv4_tcp {
        .family = AF_INET,
        .protocol = IPPROTO_TCP
    };
    DiagQuery ipv4_udp {
        .family = AF_INET,
        .protocol = IPPROTO_UDP
    };
    DiagQuery ipv6_tcp {
        .family = AF_INET6,
        .protocol = IPPROTO_TCP
    };
    DiagQuery ipv6_udp {
        .family = AF_INET6,
        .protocol = IPPROTO_UDP
    };

    std::vector<SocketInfo> sockets;
    status_msg socket_req_ans1 = socket_req(proc_info.socket_inodes, sockets, ipv4_tcp);
    if (socket_req_ans1 != status_msg::success) {
        return socket_req_ans1;
    }
    status_msg socket_req_ans2 = socket_req(proc_info.socket_inodes, sockets, ipv4_udp);
    if (socket_req_ans2 != status_msg::success) {
        return socket_req_ans2;
    }
    status_msg socket_req_ans3 = socket_req(proc_info.socket_inodes, sockets, ipv6_tcp);
    if (socket_req_ans3 != status_msg::success) {
        return socket_req_ans3;
    }
    status_msg socket_req_ans4 = socket_req(proc_info.socket_inodes, sockets, ipv6_udp);
    if (socket_req_ans4 != status_msg::success) {
        return socket_req_ans4;
    }

    if (need_print_about_proc == true) {
        print_process_info(proc_info);
        print_socket_info(sockets, pid_detail);
    }

    return status_msg::success;
}
