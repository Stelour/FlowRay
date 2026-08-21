#include "main.h"

int main(int argc, char* argv[]) {
    CLI::App app{"FlowRay"};
    int pid{};
    CLI::Option *op_pid = app.add_option("--pid,-p", pid, "Process ID");
    CLI11_PARSE(app, argc, argv);

    if (*op_pid) {
        start_pid(pid);
    }
    return 0;
}