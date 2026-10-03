#ifndef FLOWRAY_PID_H
#define FLOWRAY_PID_H

#include "data.h"

#include <cstdint>
#include <vector>

status_msg start_pid(const std::vector<std::uint32_t>& pids, bool pid_tree, bool pid_detail, bool proc_live, const std::string& proc_name);
void push_pid_tree(int pid, std::vector<std::uint32_t>& proc_pid);
status_msg get_proc_sockets(
    const std::vector<uint32_t>& pids,
    bool pid_tree,
    std::vector<ProcessInfo>& processes,
    std::vector<SocketInfo>& sockets, SocketFdMap* socket_fds
    );

#endif //FLOWRAY_PID_H
