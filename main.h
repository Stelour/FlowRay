#ifndef FLOWRAY_MAIN_H
#define FLOWRAY_MAIN_H
#include <iostream>
#include <filesystem>
#include <CLI/CLI.hpp>
#include <string>
#include <fstream>

enum class ErrorCode {
    success,
    incorrect_pid,
    file_not_found
};

ErrorCode start_pid(int pid);

#endif //FLOWRAY_MAIN_H
