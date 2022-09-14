/*
 * Copyright (c) Granulate. All rights reserved.
 * Licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#include "PyPerfNativeStackTrace.h"

#include <sys/uio.h>
#include <errno.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <time.h>     
#include <chrono>
#include <thread>

#include "PyPerfLoggingHelper.h"

namespace ebpf {
namespace pyperf {

// Ideally it was preferable to save this as the context in libunwind accessors, but it's already used by UPT
const uint16_t NativeStackTrace::CacheMaxSizeMB = 56;
const uint16_t NativeStackTrace::CacheMaxTTL = 300; // In seconds
const uint8_t *NativeStackTrace::stack = NULL;
size_t NativeStackTrace::stack_len = 0;
uintptr_t NativeStackTrace::sp = 0;
uintptr_t NativeStackTrace::ip = 0;
time_t  NativeStackTrace::now;
UnwindCache NativeStackTrace::cache;


NativeStackTrace::NativeStackTrace(uint32_t pid, const unsigned char *raw_stack,
                                   size_t stack_len, uintptr_t ip, uintptr_t sp) : error_occurred(false) {
  NativeStackTrace::stack = raw_stack;
  NativeStackTrace::stack_len = stack_len;
  NativeStackTrace::ip = ip;
  NativeStackTrace::sp = sp;
  NativeStackTrace::now = time(NULL);

  if (stack_len == 0) {
    return;
  }

  unw_accessors_t my_accessors = _UPT_accessors;
  my_accessors.access_mem = NativeStackTrace::access_mem;
  my_accessors.access_reg = NativeStackTrace::access_reg;

  // The UPT implementation of these functions uses ptrace. We want to make sure they aren't getting called
  my_accessors.access_fpreg = NULL;
  my_accessors.resume = NULL;
  unw_addr_space_t as;
  unw_cursor_t cursor;
  void *upt;
  int res;

  // Pseudo-proactive way of implementing TTL - whenever any call is made, all expired entries are removed
  cache_eviction(cache);

  // Check whether the entry for the process ID is presented in the cache
  if (!is_cached(cache, pid)) {
    logInfo(2,"The given key %d is not presented in the cache\n", pid);
   
    as = unw_create_addr_space(&my_accessors, 0);
    upt = _UPT_create(pid);
    if (!upt) {
      this->symbols.push_back(std::string("[Error _UPT_create (system OOM)]"));
      this->error_occurred = true;
      cleanup(upt, as); 
      return;
    }

    res = unw_init_remote(&cursor, as, &upt);  
    if (res) {
      std::ostringstream error;
      error << "[Error unw_init_remote (" << unw_strerror(res) << ")]";
      this->symbols.push_back(error.str());
      this->error_occurred = true;
      cleanup(upt, as); 
      return;
    }
    
    // Put to the cache
    cache_put(cache, pid, cursor, as, upt);

  } else {
    logInfo(2,"Found entry for the given key %d in the cache\n", pid);
    // Get from the cache
    UnwindCacheEntry cached_entry = cache_get(cache, pid);
    cursor = cached_entry.cursor;
    as = cached_entry.as;
    upt = cached_entry.upt;
  }

  do {
    unw_word_t offset;
    char sym[256];

    // TODO: This function is very heavy. We should try to do some caching here, maybe in the
    //       underlying UPT function.
    res = unw_get_proc_name(&cursor, sym, sizeof(sym), &offset);
    if (res == 0) {
      this->symbols.push_back(std::string(sym));
    } else {
      unw_word_t ip;
      unw_get_reg(&cursor, UNW_REG_IP, &ip);
      unw_word_t sp;
      unw_get_reg(&cursor, UNW_REG_SP, &sp);
      logInfo(2,
              "IP=0x%lx -- error: unable to obtain symbol name for this frame - %s "
              "(frame SP=0x%lx)\n",
              ip, unw_strerror(res), sp);
      this->symbols.push_back(std::string("(missing)"));
      this->error_occurred = true;
      break;
    }

    // Unwind only until we get to the function from which the current Python function is executed.
    // On Python3 the main loop function is called "_PyEval_EvalFrameDefault", and on Python2 it's
    // "PyEval_EvalFrameEx".
    if (memcmp(sym, "_PyEval_EvalFrameDefault",
                sizeof("_PyEval_EvalFrameDefault")) == 0 ||
        memcmp(sym, "PyEval_EvalFrameEx", sizeof("PyEval_EvalFrameEx")) == 0)
        {
      break;
    }
  } while (unw_step(&cursor) > 0);

}

void NativeStackTrace::cleanup(void *upt, unw_addr_space_t as) {
  if (upt) {
    _UPT_destroy(upt);
  }
  if (as) {
    unw_destroy_addr_space(as);
  }
}

int NativeStackTrace::access_reg(unw_addr_space_t as, unw_regnum_t regnum,
                                 unw_word_t *valp, int write, void *arg) {
  if (regnum == UNW_REG_SP) {
    if (write) {
      logInfo(2, "Libunwind attempts to write to SP\n");
      return -UNW_EINVAL;
    }

    *valp = NativeStackTrace::sp;
    return 0;
  }
  else if (regnum == UNW_REG_IP) {
    if (write) {
      logInfo(2, "Libunwind attempts to write to IP\n");
      return -UNW_EINVAL;
    }

    *valp = NativeStackTrace::ip;
    return 0;
  }
  else {
    logInfo(3, "Libunwind attempts to %s regnum %d\n", write ? "write" : "read", regnum);
    return -UNW_EBADREG;
  }
}

int NativeStackTrace::access_mem(unw_addr_space_t as, unw_word_t addr,
                                 unw_word_t *valp, int write, void *arg) {
  if (write) {
    logInfo(3, "Libunwind unexpected mem write attempt\n");
    return -UNW_EINVAL;
  }

  // Subtract 128 for x86-ABI red zone
  const uintptr_t top_of_stack = NativeStackTrace::sp - 128;
  const uintptr_t stack_start = top_of_stack & ~(getpagesize() - 1);
  const uintptr_t stack_end = stack_start + NativeStackTrace::stack_len;

  if (addr >= top_of_stack && addr < stack_end) {
    memcpy(valp, &stack[addr - stack_start], sizeof(*valp));
    return 0;
  } else if ((addr >= stack_end && addr < stack_end + getpagesize() * 32) ||
             (addr >= stack_start - getpagesize() * 32 && addr < top_of_stack)) {
    // Memory accesses around the pages we copied are assumed to be accesses to the
    // stack that we shouldn't allow
    logInfo(2, "Libunwind attempt to access stack at not-copied address 0x%lx (SP=0x%lx)\n", addr,
            NativeStackTrace::sp);
    return -UNW_EINVAL;
  }

  // Naive cache for this kind of requests.
  // The improvement here is pretty significant - libunwind performs consecutive calls with the same
  // address, so it has around 70-80% hit rate
  // TODO: Maybe we can improve it further by cacheing the entire page
  static unw_word_t last_valp = 0;
  static unw_word_t last_addr = 0;

  if (addr == last_addr) {
    *valp = last_valp;
    return 0;
  }

  struct iovec local = {valp, sizeof(*valp)};
  struct iovec remote = {(void *)addr, sizeof(*valp)};

  if (process_vm_readv(*(pid_t *)arg, &local, 1, &remote, 1, 0) ==
      sizeof(*valp)) {
    last_addr = addr;
    last_valp = *valp;
    return 0;
  }

  logInfo(2, "Write to 0x%lx using process_vm_readv failed with %d (%s)\n", addr, errno, strerror(errno));
  return -UNW_EINVAL;
}

std::vector<std::string> NativeStackTrace::get_stack_symbol() const {
  return symbols;
}

bool NativeStackTrace::error_occured() const {
  return error_occurred;
}

bool NativeStackTrace::is_cached(const UnwindCache &map, const uint32_t &key) {
  try {
      map.at(key);
      return true;
  }
  catch (const std::out_of_range&) {
      logInfo(2, "No entry for %d in the cache\n", key);
  }
  return false;
}

UnwindCacheEntry NativeStackTrace::cache_get(const UnwindCache &map, const uint32_t &key) {
  const UnwindCacheEntry & entry = map.at(key);
  return entry;
}

// cache_put adds a new entry to the unwind cache if the capacity allows
void NativeStackTrace::cache_put(UnwindCache &mp, const uint32_t &key, const unw_cursor_t cursor, const unw_addr_space_t as, void *upt) {  
  // Check available capacity
  if (cache_size() > NativeStackTrace::CacheMaxSizeMB*1024*1024 - cache_single_entry_size()) { 
    logInfo(2, "The cache usage is %.2f MB, close to reaching the max memory usage (%d MB)\n", cache_size_KB()/1024, NativeStackTrace::CacheMaxSizeMB);
    logInfo(2, "Skipping adding an entry for %d to the cache\n", key);     
    return;
  }

  UnwindCacheEntry entry = {cursor, as, upt, now};
  mp[key] = entry;
  logInfo(2, "New entry for %d was added to the cache\n", key);
}

// cache_delete_key removes the element from the cache and destroys unwind address space and UPT
// to ensure that all memory and other resources are freed up
bool NativeStackTrace::cache_delete_key(UnwindCache &mp, const uint32_t &key) {
  UnwindCacheEntry e;
  try {
    e = cache_get(mp, key);
  }
  catch (const std::out_of_range&) {
    logInfo(2, "Failed to delete entry for %d: no such key in the cache\n", key);
    return false;
  }

  mp.erase(key);
  cleanup(e.upt, e.as);
  logInfo(2, "The entry for %d was deleted from the cache\n", key);
  return true;
}

// cache_single_entry_size returns the number of bytes taken by single entry
uint32_t NativeStackTrace::cache_single_entry_size() const {  
  return sizeof(decltype(cache)::key_type) + sizeof(decltype(cache)::mapped_type);
}

// cache_size returns the number of bytes currently in use by the cache
uint32_t NativeStackTrace::cache_size() const {  
  return sizeof(cache) + cache.size()*cache_single_entry_size();
}

// cache_size_KB returns the number of kilobytes currently in use by the cache
float NativeStackTrace::cache_size_KB() const {  
  return cache_size()/1024;
}

// cache_eviction removes elements older than 5 minutes (CacheMaxTTL=300)
void NativeStackTrace::cache_eviction(UnwindCache &mp) {
  std::vector<uint32_t> keys_to_delete;
  float _prev_cache_size = cache_size_KB();

  for(std::map<uint32_t, UnwindCacheEntry>::iterator iter = mp.begin(); iter != mp.end(); ++iter)
  {
    uint32_t k =  iter->first;
    const UnwindCacheEntry & e =  iter->second;
    if (std::abs(difftime(e.timestamp, NativeStackTrace::now)) > NativeStackTrace::CacheMaxTTL) {
      // exceeding TTL
      keys_to_delete.push_back(k);
    }
  }

  // Delete expired entries
  for( size_t i = 0; i < keys_to_delete.size(); i++ ) {
      cache_delete_key(mp, keys_to_delete[i]);
  }

  if (keys_to_delete.size() > 0) {
    float _cache_size = cache_size_KB();
    logInfo(2,"Evicted %d item(s) from the cache\n", keys_to_delete.size());
    logInfo(2,"The cache usage after eviction action is %.2f KB (released %.2f KB)\n", _cache_size, _prev_cache_size - _cache_size);    
  }
}

}  // namespace pyperf
}  // namespace ebpf
