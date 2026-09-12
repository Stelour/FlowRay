#ifndef FLOWRAY_OUTPUT_H
#define FLOWRAY_OUTPUT_H

#include "data.h"

#include <vector>

void print_socket_info(const std::vector<SocketInfo>& sockets, bool detail);
void print_process_info(const ProcessInfo& proc_info);

#endif //FLOWRAY_OUTPUT_H
