#include "main.h"

int main(int argc, char* argv[]) {
    CLI::App app{"FlowRay - linux application network activity analyzer"};
    int pid{};
    CLI::Option *op_pid = app.add_option("--pid,-p", pid, "Process ID");
    bool pid_tree = false;
    CLI::Option *op_tree = app.add_flag("--tree,-t", pid_tree, "Show process tree");
    op_tree->needs(op_pid);
    bool pid_detail = false;
    CLI::Option *op_detail = app.add_flag("--detail,-d", pid_detail, "Show detail information about socket");
    op_detail->needs(op_pid);
    CLI11_PARSE(app, argc, argv);

    if (*op_pid) {
        start_pid(pid, true, pid_tree, pid_detail);
    }
    return 0;
}