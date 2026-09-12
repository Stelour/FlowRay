#include "pid.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

static bool is_number(const std::string& s) {
    if (s.empty()) return false;
    for (char const &c : s) {
        if (!std::isdigit(c)) return false;
    }
    return true;
}

static std::uint32_t get_ppid_proc(std::uint32_t pid) {
    std::ifstream file_stat("/proc/"  + std::to_string(pid) + "/status");
    if (!file_stat.is_open()) {
        return 0;
    }
    std::string l;
    while (std::getline(file_stat, l)) {
        if (l.rfind("PPid:", 0) == 0) {
            return static_cast<uint32_t>(std::stoul(l.substr(5)));
        }
    }
    return 0;
}

static void collect_children(std::uint32_t pid,
    const std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>& children_map,
    std::vector<std::uint32_t>& proc_pid) {
    auto it = children_map.find(pid);

    if (it == children_map.end()) {
        return;
    }

    for (const auto child_pid : it->second) {
        proc_pid.push_back(child_pid);
        collect_children(child_pid, children_map,proc_pid);
    }
}

void push_pid_tree(int pid, std::vector<std::uint32_t>& proc_pid) {
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> children_map;
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (entry.is_directory()) {
            std::string folder_name = entry.path().filename().string();
            if (is_number(folder_name)) {
                auto pid_child = static_cast<uint32_t>(std::stoul(folder_name));
                const auto ppid = get_ppid_proc(pid_child);
                if (ppid == 0) {
                    continue;
                }
                children_map[ppid].push_back(pid_child);
            }
        }
    }
    collect_children(static_cast<std::uint32_t>(pid), children_map,proc_pid);
}