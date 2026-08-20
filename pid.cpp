#include <filesystem>

int check_pid_is_correct(int pid) {
    std::filesystem::path dir_path = "/proc/" + std::to_string(pid);
    return std::filesystem::is_directory(dir_path);
}