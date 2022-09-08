/*
 * Copyright (c) Granulate. All rights reserved.
 * Copyright (c) Facebook, Inc.
 *
 * This file has been modified from its original version by Granulate.
 * Modifications are licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#pragma once

#include <vector>

#include "PyPerfType.h"

namespace ebpf {
namespace pyperf {

class PyPerfProfiler;

class PyPerfSampleProcessor {
 public:
  virtual void prepare() {};
  virtual void processSamples(const std::vector<PyPerfSample>& samples,
                              PyPerfProfiler* util) = 0;
};

}  // namespace pyperf
}  // namespace ebpf
