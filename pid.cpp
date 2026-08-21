#include "main.h"

bool check_pid_is_correct(const std::string& dir_path) {
    return std::filesystem::is_directory(dir_path);
}

void find_socket_inodes(
    const std::string& dir_path,
    std::vector<std::string>& socket_list,
    std::unordered_set<std::uint32_t>& socket_inodes) {
    for (const auto& entry : std::filesystem::directory_iterator(dir_path + "/fd")) {
        std::string cur_fd = std::filesystem::read_symlink(entry.path());
        if (cur_fd.substr(0, 7) == "socket:") {
            socket_list.push_back(cur_fd);
            socket_inodes.insert(std::stoul(cur_fd.substr(8, cur_fd.length() - 8)));
        }
    }
}

void get_process_info(const ProcessInfo& proc_info) {
    std::cout << "PID: " << proc_info.pid << std::endl;
    std::cout << "Process name: " << proc_info.name << std::endl;
    std::cout << std::endl;
    std::cout << "Sockets:" << std::endl;
    for (const std::string& s : proc_info.socket_list) {
        std::cout << s << std::endl;
    }
}

ErrorCode start_pid(int pid) {
    std::string str_pid = std::to_string(pid);
    std::string dir_path = "/proc/" + str_pid;
    if (check_pid_is_correct(dir_path) == false) {
        std::cerr << "ERROR: incorrect PID" << std::endl;
        return ErrorCode::incorrect_pid;
    }

    std::ifstream file_pid_comm(dir_path + "/comm");
    std::string process_name;
    std::getline(file_pid_comm, process_name);

    std::vector<std::string> socket_list = {};
    std::unordered_set<std::uint32_t> socket_inodes = {};
    find_socket_inodes(dir_path, socket_list, socket_inodes);

    ProcessInfo proc_info = {pid, process_name, dir_path, socket_list, socket_inodes};
    get_process_info(proc_info);

    return ErrorCode::success;
}
