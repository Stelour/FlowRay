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
#include <thread>
#include <chrono>

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

status_msg get_proс_sockets(
    const std::vector<uint32_t>& pids,
    bool pid_tree,
    std::vector<ProcessInfo>& processes,
    std::vector<SocketInfo>& sockets
    ) {
    processes.clear();
    sockets.clear();
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


    for (const auto& query : queries) {
        if (socket_req(socket_inodes, sockets, query) != status_msg::success) {
            return status_msg::error;
        }
    }
    return status_msg::success;
}

status_msg start_pid(const std::vector<std::uint32_t>& pids, bool pid_tree, bool pid_detail, bool proc_live) {
    std::vector<ProcessInfo> processes;
    std::vector<SocketInfo> sockets;
    if (get_proс_sockets(pids, pid_tree, processes, sockets) != status_msg::success) {
        std::cerr << "ERROR: failed to get proc_sockets" << std::endl;
        return status_msg::error;
    }

    print_process_info(processes);
    print_socket_info(sockets, pid_detail);

    if (proc_live) {
        std::cout << std::endl;
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::vector<ProcessInfo> new_processes;
            std::vector<SocketInfo> new_sockets;
            if (get_proс_sockets(pids, pid_tree, new_processes, new_sockets) != status_msg::success) {
                continue;
            }

            print_socket_diff(new_sockets, sockets, pid_detail);

            processes = std::move(new_processes);
            sockets = std::move(new_sockets);
        }
    }

    return status_msg::success;
}
