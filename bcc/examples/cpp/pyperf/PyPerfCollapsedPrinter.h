/*
 * Copyright (c) Granulate. All rights reserved.
 * Licensed under the AGPL3 License. See LICENSE.txt for license information.
 */
#pragma once

#include "PyPerfSampleProcessor.h"
#include <cstdio>
#include <limits.h>

namespace ebpf {
namespace pyperf {

class PyPerfCollapsedPrinter : public PyPerfSampleProcessor {
 public:
  PyPerfCollapsedPrinter(std::string& output);

  void prepare() override;
  void processSamples(const std::vector<PyPerfSample>& samples,
                      PyPerfProfiler* util) override;

 private:
  std::string output_;
  char final_path[PATH_MAX];
  std::FILE *output_file;

  void open_new();
  const char *sample_strerror(enum error_code error);
};

}  // namespace pyperf
}  // namespace ebpf
