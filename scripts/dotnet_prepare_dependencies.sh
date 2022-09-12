#!/usr/bin/env bash
#
# Copyright (c) Granulate. All rights reserved.
# Licensed under the AGPL3 License. See LICENSE.md in the project root for license information.
#
# set -euo pipefail

declare -a deps=("libclrjit.so"
                 "libhostpolicy.so"
                 "libcoreclr.so" 
                 "libSystem.Native.so"
                 "Microsoft.CSharp.dll"
                 "Microsoft.NETCore.App.deps.json"
                 "Microsoft.Win32.Primitives.dll"
                 "mscorlib.dll"
                 "netstandard.dll"
                 "System.ObjectModel.dll"
                 "System.Collections.Concurrent.dll"
                 "System.Collections.dll"
                 "System.ComponentModel.dll"
                 "System.ComponentModel.Primitives.dll"
                 "System.ComponentModel.TypeConverter.dll"
                 "System.Console.dll"
                 "System.Core.dll"
                 "System.Data.Common.dll"
                 "System.Data.DataSetExtensions.dll"
                 "System.Data.dll"
                 "System.Diagnostics.Process.dll"
                 "System.Diagnostics.Tracing.dll"
                 "System.dll"
                 "System.IO.FileSystem.dll"
                 "System.IO.FileSystem.Primitives.dll"
                 "System.Linq.dll"
                 "System.Linq.Expressions.dll"
                 "System.Memory.dll"
                 "System.Private.CoreLib.dll"
                 "System.Private.Uri.dll" 
                 "System.Runtime.dll"
                 "System.Runtime.Extensions.dll"
                 "System.Runtime.InteropServices.dll" 
                 "System.Runtime.InteropServices.RuntimeInformation.dll" 
                 "System.Text.RegularExpressions.dll"
                 "System.Threading.Channels.dll" 
                 "System.Threading.dll"
                 "System.Threading.Overlapped.dll" 
                 "System.Threading.Tasks.dll" 
                 "System.Threading.Thread.dll"
                 "System.Threading.ThreadPool.dll"
                 "System.IO.Pipes.dll" 
                 "System.Net.Sockets.dll" 
                 "System.Net.Primitives.dll" 
                 "System.Security.Principal.dll" 
                 "System.IO.dll"
                 "System.Security.Cryptography.Algorithms.dll"
                 "System.Security.Cryptography.Primitives.dll"
                 "libSystem.Security.Cryptography.Native.OpenSsl.so"
                 "System.Runtime.CompilerServices.Unsafe.dll"
                 "System.Diagnostics.TraceSource.dll"
                 "System.Reflection.Emit.ILGeneration.dll"
                 "System.Reflection.Emit.Lightweight.dll"
                 "System.Reflection.Primitives.dll"
                 )
mkdir -p /tmp/dotnet/deps
for i in "${deps[@]}"
do
   cp "/usr/share/dotnet/shared/Microsoft.NETCore.App/6.0.7/$i" "/tmp/dotnet/deps/$i"
done

 