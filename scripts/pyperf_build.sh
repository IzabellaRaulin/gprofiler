#!/usr/bin/env bash
#
# Copyright (c) Granulate. All rights reserved.
# Licensed under the AGPL3 License. See LICENSE.md in the project root for license information.
#
set -e

git clone --depth 1 -b aarch64 https://github.com/Granulate/bcc.git && cd bcc && git reset --hard 918fc3138beac21262f5f3b96f92b37b97837bf0

mkdir build
cd build
cmake -DPYTHON_CMD=python3 -DINSTALL_CPP_EXAMPLES=y -DCMAKE_INSTALL_PREFIX=/bcc/root -DENABLE_LLVM_SHARED=1 ..
make -C examples/cpp/pyperf -j -l VERBOSE=1 install
