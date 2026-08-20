#include <iostream>
#include <CLI/CLI.hpp>

int check_pid_is_correct(int pid);

int main(int argc, char* argv[]) {
    CLI::App app{"FlowRay network analyzer"};
    int pid{};
    app.add_option("--pid,-p", pid, "Process ID");
    CLI11_PARSE(app, argc, argv);

    if (pid) {
        std::cout << "PID: " << pid << '\n';
        if (check_pid_is_correct(pid) == false) {
            std::cout << "ERROR: incorrect PID" << '\n';
        }
    }

    return 0;
}