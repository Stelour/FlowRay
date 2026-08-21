#include "main.h"

bool check_pid_is_correct(const std::string& dir_path) {
    return std::filesystem::is_directory(dir_path);
}

ErrorCode start_pid(int pid) {
    std::string str_pid = std::to_string(pid);
    std::string dir_path = "/proc/" + str_pid;

    std::cout << "PID: " << pid << std::endl;

    if (check_pid_is_correct(dir_path) == false) {
        std::cerr << "ERROR: incorrect PID" << std::endl;
        return ErrorCode::incorrect_pid;
    }

    std::ifstream file_pid_comm(dir_path + "/comm");
    std::string process_name;
    std::getline(file_pid_comm, process_name);

    std::cout << "Process name: " << process_name << std::endl;

    return ErrorCode::success;
}

