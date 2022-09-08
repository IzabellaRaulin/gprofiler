/*
 * Copyright (c) Granulate. All rights reserved.
 * Copyright (c) Facebook, Inc.
 *
 * This file has been modified from its original version by Granulate.
 * Modifications are licensed under the AGPL3 License. See LICENSE.txt for license information.
 */
#pragma once

#include <vector>
#include <string>
#include <sys/types.h>

namespace ebpf {
namespace pyperf {

bool filter_kernel_thread(int pid);

bool getRunningPids(std::vector<int>& output);

bool get_pid_path(pid_t pid, std::string& path, std::string& out_path);

}  // namespace pyperf
}  // namespace ebpf
