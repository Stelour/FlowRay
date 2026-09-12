#ifndef FLOWRAY_PID_H
#define FLOWRAY_PID_H

#include "data.h"

#include <cstdint>
#include <vector>

status_msg start_pid(int pid, bool need_print_about_proc, bool pid_tree, bool pid_detail);
void push_pid_tree(int pid, std::vector<std::uint32_t>& proc_pid);

#endif //FLOWRAY_PID_H
