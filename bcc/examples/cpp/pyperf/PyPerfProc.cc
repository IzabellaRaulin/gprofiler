/*
 * Copyright (c) Granulate. All rights reserved.
 * Copyright (c) Facebook, Inc.
 *
 * This file has been modified from its original version by Granulate.
 * Modifications are licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#include "PyPerfProc.h"
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

namespace ebpf {
namespace pyperf {

/**
Return true if pid is not a kernel thread.
*/
bool filter_kernel_thread(int pid) {
  static char exe[PATH_MAX];
  snprintf(exe, sizeof(exe), "/proc/%d/exe", pid);
  ssize_t len = readlink(exe, exe, sizeof(exe) - 1);
  if (len < 0) {
    // kernel threads return ENOENT
    if (errno != ENOENT) {
      fprintf(stderr, "Error reading link /proc/%d/exe\n", pid);
    }
    return false;
  }
  return true;
}

bool getRunningPids(std::vector<int>& output) {
  auto dir = opendir("/proc/");
  if (!dir) {
    std::fprintf(stderr, "Open /proc failed: %d\n", errno);
    return false;
  }

  dirent* result = nullptr;
  do {
    if ((result = readdir(dir))) {
      std::string basename = result->d_name;
      if (basename == "." || basename == "..") {
        continue;
      }

      int pid;
      try {
        pid = std::stoi(basename);
      } catch (const std::exception& e) {
        continue;
      }

      std::string fullpath = "/proc/" + basename;
      struct stat st;
      if (stat(fullpath.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        continue;
      }

      output.push_back(pid);
    }
  } while (result);

  if (closedir(dir) == -1) {
    std::fprintf(stderr, "Close /proc failed: %d\n", errno);
    return false;
  }

  return true;
}

bool get_pid_path(pid_t pid, std::string& path, std::string& out_path) {
  static char pathbuf[256];
  int result = std::snprintf(pathbuf, sizeof(pathbuf), "/proc/%d/root%s", pid, path.c_str());
  if (result < 0 || (size_t)result >= sizeof(pathbuf)) {
    std::fprintf(stderr, "[%d] Path too long? %s\n", pid, path.c_str());
    return false;
  }
  out_path = std::string{pathbuf};
  return true;
}

}  // namespace pyperf
}  // namespace ebpf
