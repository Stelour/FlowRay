#include "main.h"

bool check_pid_is_correct(const std::string& dir_path) {
    return std::filesystem::is_directory(dir_path);
}

void get_process_info(const ProcessInfo& proc_info) {
    std::cout << "PID: " << proc_info.pid << std::endl;
    std::cout << "Process name: " << proc_info.name << std::endl;
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
    ProcessInfo proc_info = {pid, process_name, dir_path};
    get_process_info(proc_info);
    return ErrorCode::success;
}

