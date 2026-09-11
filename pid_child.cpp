#include "main.h"

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

void push_pid_tree(int pid, std::vector<std::uint32_t>& proc_pid) {
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (entry.is_directory()) {
            std::string folder_name = entry.path().filename().string();
            if (is_number(folder_name)) {
                auto pid_child = static_cast<uint32_t>(std::stoul(folder_name));
                if (pid == get_ppid_proc(pid_child)) {
                    proc_pid.push_back(pid_child);
                    push_pid_tree(static_cast<int>(pid_child), proc_pid);
                }
            }
        }
    }
}