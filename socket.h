#ifndef FLOWRAY_SOCKET_H
#define FLOWRAY_SOCKET_H

#include "data.h"

#include <vector>

status_msg socket_req(
    const std::unordered_map<std::uint32_t, std::set<std::uint32_t>>& target_inodes,
    std::vector<SocketInfo>& sockets,
    DiagQuery socket_diag_query);

#endif //FLOWRAY_SOCKET_H
