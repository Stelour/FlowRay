#include "main.h"

bool check_pid_is_correct(const std::string& dir_path) {
    return std::filesystem::is_directory(dir_path);
}

void find_socket_inodes(
    const std::string& dir_path,
    std::unordered_set<std::uint32_t>& socket_inodes) {
    for (const auto& entry : std::filesystem::directory_iterator(dir_path + "/fd")) {
        std::error_code ec;
        std::string cur_fd = std::filesystem::read_symlink(entry.path(), ec);
        if (ec) {
            continue;
        }
        if (cur_fd.starts_with("socket:[")) {
            socket_inodes.insert(std::stoul(
                cur_fd.substr(cur_fd.find('[') + 1, cur_fd.find(']') - cur_fd.find('[') - 1)));
        }
    }
}

void print_process_info(const ProcessInfo& proc_info) {
    std::cout << "PID: " << proc_info.pid << std::endl;
    std::cout << "Process name: " << proc_info.name << std::endl;
    std::cout << std::endl;
    std::cout << "Socket inodes:" << std::endl;
    for (const std::uint32_t& s : proc_info.socket_inodes) {
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

    std::unordered_set<std::uint32_t> socket_inodes = {};
    find_socket_inodes(dir_path, socket_inodes);

    ProcessInfo proc_info = {pid, process_name, dir_path, socket_inodes};
    print_process_info(proc_info);

    return ErrorCode::success;
}
