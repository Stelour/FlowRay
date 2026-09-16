#ifndef FLOWRAY_OUTPUT_H
#define FLOWRAY_OUTPUT_H

#include "data.h"

#include <vector>

void print_socket_info(const std::vector<SocketInfo>& sockets, bool detail);
void print_process_info(const std::vector<ProcessInfo>& processes);
void print_socket_diff(const std::vector<SocketInfo>& prev, const std::vector<SocketInfo>& cur, bool detail);

#endif //FLOWRAY_OUTPUT_H
