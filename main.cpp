#include "main.h"

int main(int argc, char* argv[]) {
    CLI::App app{"FlowRay - linux application network activity analyzer"};

    std::uint32_t pid{};
    CLI::Option *op_pid = app.add_option(
        "--pid,-p",
        pid,
        "Analyze a process by PID"
        );

    std::string proc_name;
    CLI::Option *op_name = app.add_option(
        "--name,-n",
        proc_name,
        "Analyze all processes with the specified name"
        );

    bool pid_tree = false;
    CLI::Option *op_tree = app.add_flag(
        "--tree,-t",
        pid_tree,
        "Include descendant processes in the analysis"
        );
    // op_tree->needs(op_pid);

    bool pid_detail = false;
    CLI::Option *op_detail = app.add_flag(
        "--detail,-d",
        pid_detail,
        "Show detailed socket information, including PID and inode"
        );
    // op_detail->needs(op_pid);

    op_pid->excludes(op_name);
    op_name->excludes(op_pid);

    CLI11_PARSE(app, argc, argv);

    if (!(*op_pid || *op_name)) {
        if (pid_tree || pid_detail) {
            std::cerr << "ERROR: --tree and --detail require --pid or --name" << std::endl;
            return -1;
        }
        std::cout << app.help();
        return 0;
    }

    if (*op_pid) {
        if (start_pid({pid}, true, pid_tree, pid_detail) != status_msg::success) {
            std::cerr << "ERROR: failed to start process pid " << std::endl;
            return -1;
        }
    } else if (*op_name) {
        auto pids = find_pids_by_name(proc_name);
        if (pids.empty()) {
            std::cerr << "ERROR: process " << proc_name << " not found" << std::endl;
            return -1;
        }
        if (start_pid(pids, true, pid_tree, pid_detail) != status_msg::success) {
            std::cerr << "ERROR: failed to start process pid " << std::endl;
            return -1;
        }
    }
    return 0;
}