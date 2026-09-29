#ifndef FLOWRAY_EBPF_MONITOR_H
#define FLOWRAY_EBPF_MONITOR_H

#include <cstdint>
#include <string>
#include <vector>

int ebpf_start(const std::vector<std::uint32_t>& pids, const std::string& proc_name, bool pid_tree);

#endif //FLOWRAY_EBPF_MONITOR_H
