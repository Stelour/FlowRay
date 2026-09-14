#ifndef FLOWRAY_PROC_NAME_H
#define FLOWRAY_PROC_NAME_H

#include "data.h"

#include <vector>

std::vector<std::uint32_t> find_pids_by_name(const std::string& proc_name);

#endif //FLOWRAY_PROC_NAME_H
