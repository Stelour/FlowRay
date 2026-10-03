#ifndef FLOWRAY_DATA_H
#define FLOWRAY_DATA_H

#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <chrono>
#include <unordered_map>

enum class status_msg {
    success,
    error
};

struct ProcessInfo {
    std::uint32_t pid{};
    std::string name;
};

struct DiagQuery {
    std::uint8_t family{};
    std::uint8_t protocol{};
};

struct SocketFdRef {
    std::uint32_t pid;
    int fd;
};

using SocketFdMap = std::unordered_map<std::uint32_t, std::vector<SocketFdRef>>;

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

struct LiveSocket {
    SocketInfo socket;

    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;

    bool active{};
};

#endif //FLOWRAY_DATA_H
