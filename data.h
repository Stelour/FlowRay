#ifndef FLOWRAY_DATA_H
#define FLOWRAY_DATA_H

#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <unordered_map>

enum class status_msg {
    success,
    error
};

struct ProcessInfo {
    int pid{};
    std::string name;
    std::filesystem::path dir_path;
};

struct DiagQuery {
    std::uint8_t family{};
    std::uint8_t protocol{};
};

struct SocketInfo {
    std::uint8_t family{};
    std::uint8_t protocol{};

    std::set<std::uint32_t> pids{};
    std::uint32_t inode{};
    std::uint32_t uid{};
    std::uint8_t state{};

    std::string local_ip;
    std::uint16_t local_port{};

    std::string remote_ip;
    std::uint16_t remote_port{};
};

#endif //FLOWRAY_DATA_H
