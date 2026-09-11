#ifndef FLOWRAY_MAIN_H
#define FLOWRAY_MAIN_H

#include <iostream>
#include <filesystem>
#include <CLI/CLI.hpp>
#include <string>
#include <fstream>
#include <vector>
#include <unordered_set>

enum class status_msg {
    success,
    error
};

struct ProcessInfo {
    int pid{};
    std::string name;
    std::filesystem::path dir_path;
    std::unordered_set<std::uint32_t> socket_inodes;
};

struct DiagQuery {
    std::uint8_t family{};
    std::uint8_t protocol{};
};

struct SocketInfo {
    std::uint8_t family{};
    std::uint8_t protocol{};

    std::uint32_t inode{};
    std::uint32_t uid{};
    std::uint8_t state{};

    std::string local_ip;
    std::uint16_t local_port{};

    std::string remote_ip;
    std::uint16_t remote_port{};
};

status_msg start_pid(int pid, bool need_print_about_proc, bool pid_tree);
status_msg socket_req(
    const std::unordered_set<std::uint32_t>& target_inodes,
    std::vector<SocketInfo>& sockets,
    DiagQuery socket_diag_query);
void push_pid_tree(int pid, std::vector<std::uint32_t>& proc_pid);

#endif //FLOWRAY_MAIN_H
