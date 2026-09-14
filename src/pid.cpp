#include "../headers/pid.h"
#include "../headers/output.h"
#include "../headers/socket.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <array>
#include <algorithm>

static bool check_pid_is_correct(const std::string& dir_path) {
    return std::filesystem::is_directory(dir_path);
}

static void find_socket_inodes(
    const std::string& dir_path,
    std::unordered_map<std::uint32_t, std::set<std::uint32_t>>& socket_inodes,
    std::uint32_t proc_pid) {
    try {
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
                    ].insert(proc_pid);
            }
        }
    } catch(const std::filesystem::filesystem_error&) {
        return;
    }
}

status_msg start_pid(const std::vector<std::uint32_t>& pids, bool need_print_about_proc, bool pid_tree, bool pid_detail) {
    if (pids.empty()) {
        std::cerr << "ERROR: no processes found" << std::endl;
        return status_msg::error;
    }

    std::vector<std::uint32_t> procs_pid = pids;
    for (auto pid : pids) {
        std::string dir_path = "/proc/" + std::to_string(pid);

        if (!check_pid_is_correct(dir_path)) {
            std::cerr << "ERROR: incorrect PID " << pid << std::endl;
            return status_msg::error;
        }
    }

    if (pid_tree) {
        for (auto pid : pids) {
            push_pid_tree(pid, procs_pid);
        }
        std::sort(procs_pid.begin(), procs_pid.end());
        procs_pid.erase(
            std::unique(procs_pid.begin(), procs_pid.end()),
            procs_pid.end()
        );
    }

    // std::unordered_set<std::uint32_t> socket_inodes = {};
    std::unordered_map<std::uint32_t, std::set<std::uint32_t>> socket_inodes;
    for (auto& proc_pid : procs_pid) {
        find_socket_inodes("/proc/" + std::to_string(proc_pid), socket_inodes, proc_pid);
    }

    std::vector<ProcessInfo> processes;
    for (auto pid : procs_pid) {
        std::ifstream file("/proc/" + std::to_string(pid) + "/comm");
        if (!file) {
            continue;
        }
        std::string name;
        std::getline(file, name);
        processes.push_back({pid,name});
    }

    // req to socket
    const std::array<DiagQuery, 4> queries{{
        {AF_INET,  IPPROTO_TCP},
        {AF_INET,  IPPROTO_UDP},
        {AF_INET6, IPPROTO_TCP},
        {AF_INET6, IPPROTO_UDP}
    }};

    std::vector<SocketInfo> sockets;
    for (const auto& query : queries) {
        if (socket_req(socket_inodes, sockets, query) != status_msg::success) {
            return status_msg::error;
        }
    }

    if (need_print_about_proc == true) {
        print_process_info(processes);
        print_socket_info(sockets, pid_detail);
    }

    return status_msg::success;
}
