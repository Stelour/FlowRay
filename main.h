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

status_msg start_pid(int pid);
status_msg socket_req();

#endif //FLOWRAY_MAIN_H
