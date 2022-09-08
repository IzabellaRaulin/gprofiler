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

#include "PyPerfLoggingHelper.h"

namespace ebpf {
namespace pyperf {

// Ideally it was preferable to save this as the context in libunwind accessors, but it's already used by UPT
// static const uint32_t NativeStackTrace::CacheMaxSizeMB = 56 // Question: Prefer to limit number of entries (pid) (e.g. cache.size()) or sizeof
// const uint8_t NativeStackTrace::CacheMaxTTL = 300 // In seconds
const uint8_t *NativeStackTrace::stack = NULL;
size_t NativeStackTrace::stack_len = 0;
uintptr_t NativeStackTrace::sp = 0;
uintptr_t NativeStackTrace::ip = 0;
// bool NativeStackTrace::cache_on = true;
MAP NativeStackTrace::cache;
// using map_ref_t = std::reference_wrapper<MAP>;

// bool ok = true;


NativeStackTrace::NativeStackTrace(uint32_t pid, const unsigned char *raw_stack,
                                   size_t stack_len, uintptr_t ip, uintptr_t sp) : error_occurred(false) {
  NativeStackTrace::stack = raw_stack;
  NativeStackTrace::stack_len = stack_len;
  NativeStackTrace::ip = ip;
  NativeStackTrace::sp = sp;

  logInfo(2, "DEBUGIZA: 1. welcome\n");
 
  if (stack_len == 0) {
    logInfo(2, "DEBUGIZA: 1a. stack_len jest 0, return\n");
    return;
  }

  unw_accessors_t my_accessors = _UPT_accessors;
  my_accessors.access_mem = NativeStackTrace::access_mem;
  my_accessors.access_reg = NativeStackTrace::access_reg;

  // The UPT implementation of these functions uses ptrace. We want to make sure they aren't getting called
  my_accessors.access_fpreg = NULL;
  my_accessors.resume = NULL;

  // std::string s_debug = "DEBUGIZA: PID=" + std::to_string(pid) + "\n";
  // this->symbols.push_back(std::string(s_debug));

   // check whether the PID is presented in the cache
  unw_addr_space_t as;
  unw_cursor_t cursor;
  void *upt;
  // using map_ref_t = std::reference_wrapper<MAP_ITERATOR>;
  
  int res;
  logInfo(2,  "DEBUGIZA: 1a. cache_size=%d\n", sizeof(cache));

  if (is_cached(cache, pid) == false) {
    logInfo(2,"The given key %d is not presented in the cache\n", pid);
   
    as = unw_create_addr_space(&my_accessors, 0);

    logInfo(2,"4. Adding to cache\n");
    logInfo(2,"4a. Creating UPI...\n");
    upt = _UPT_create(pid);
    if (!upt) {
      this->symbols.push_back(std::string("[Error _UPT_create (system OOM)]"));
      this->error_occurred = true;
      goto out;
    }
    logInfo(2,"4a. Creating UPI...DONE\n");


    // TODO: It's possible to make libunwind use cache using unw_set_caching_policy, which might lead to significent
    //       performance improvement. We just need to make sure it's not dangerous. For now the overhead is good enough.
    // IZA: why unw_init_remote is used? Why not unw_init_local
    
    logInfo(2,"4b. DEBUGIZA: Init Cursor...\n");
    res = unw_init_remote(&cursor, as, &upt);  
    if (res) {
      std::ostringstream error;
      error << "[Error unw_init_remote (" << unw_strerror(res) << ")]";
      this->symbols.push_back(error.str());
      this->error_occurred = true;
      goto out;
    }
    logInfo(2,"4b. DEBUGIZA: Init Cursor...DONE\n");

    // logInfo(2,std::string("4b. DEBUGIZA: cursor= " + std::to_string(cursor) + "\n"));
    // logInfo(2,std::string("4b. DEBUGIZA: as= " + std::to_string((void *)as) + "\n"));
    // logInfo(2,std::string("4b. DEBUGIZA: upt= " + std::to_string(upt) + "\n"));

      // if (cache_size() > CacheMaxSizeMB*1024*1024 + sizeof_single_cache_entr()) {  
      //     cache_eviction()
      // }
    logInfo(2,"5. DEBUGIZA: Insert to cache...\n");
    logInfo(2,"5a. Cache size before=%d\n", cache_size());
    // Insert to cache
    // TODOIZA - odkomentuj
    cache_put(cache, pid, cursor, as, upt);
    // cache[pid] = std::make_pair(cursor, time(nullptr)); //  (cursor, as, upt, time.time());
    //cache[pid] = (cursor, time.time(), as, upt); //  (cursor, as, upt, time.time());
    // this->symbols.push_back(std::string("DEBUGIZA: Insert to cache...DONE\n"));
    //this->symbols.push_back(std::string("DEBUGIZA: Insert to cache["+ std::to_string(pid) + "=["std::to_string(cache[pid].first) + "," + std::to_string(cache[pid].second) + "] ...DONE\n"));

    logInfo(2,"5a. Cache size after=%d\n", cache_size());
    logInfo(2,"5. DEBUGIZA: Insert to cache...DONE\n");
  } else {
    logInfo(2,"55. DEBUGIZA: Reading from cache...\n");
    Object cached_value = cache_get(cache, pid);
    cursor = cached_value.cursor;
    as = cached_value.as;
    upt = cached_value.upt;
    // logInfo(2,std::string("55b. DEBUGIZA: cursor= " + std::to_string(cursor) + "\n"));
    // logInfo(2,std::string("55b. DEBUGIZA: as= " + std::to_string((void *)as) + "\n"));
    // logInfo(2,std::string("55b. DEBUGIZA: upt= " + std::to_string(upt) + "\n"));
    logInfo(2,"55. DEBUGIZA: Reading from cache...DONE\n");
  }
  

  do {
    unw_word_t offset;
    char sym[256];

    // TODO: This function is very heavy. We should try to do some caching here, maybe in the
    //       underlying UPT function.

    res = unw_get_proc_name(&cursor, sym, sizeof(sym), &offset);
    logInfo(2,"DEBUGIZA 6a. prinitng decimals=%d\n", -4);
    logInfo(2,"DEBUGIZA 6a. unw_get_proc_name res=%d\n", res);

    if (res == 0) {
      logInfo(2,"DEBUGIZA 6e. Writing symbol...\n");
      logInfo(2,"DEBUGIZA 6e. sym=%s\n", std::string(sym));
      this->symbols.push_back(std::string(sym));
      logInfo(2,"DEBUGIZA 6e. Writing symbol...DONE\n");
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


out:
  // TODO IZA - usuwanie upt i as
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

bool NativeStackTrace::is_cached(const MAP &map, const uint32_t &key) {
  try {
      map.at(key);
      logInfo(2, "DEBUGIZA 3. Key %d found in the cache\n", key);
      // this->symbols.push_back(std::string("3. Key " + std::to_string(key) +" found\n"));
      // TODO: Handle the element found.
      return true;
  }
  catch (const std::out_of_range&) {
      // this->symbols.push_back(std::string("1. Key " + std::to_string(key) +" not found\n"));
      // TODO: Deal with the missing element.
      logInfo(2, "DEBUGIZA 3. No entry for %d in the cache\n", key);
  }

  return false;
}

Object NativeStackTrace::cache_get(const MAP &map, const uint32_t &key) {
  this->symbols.push_back(std::string("4.Getting entry for pid=" + std::to_string(key) +" from the cache\n"));
  const Object & value = map.at(key);

  return value;

}

void NativeStackTrace::cache_put(MAP &map, const uint32_t &key, const unw_cursor_t cursor, const unw_addr_space_t as, void *upt) {
  Object obj = {cursor, as, upt};

  map[key] = obj;

  logInfo(2, "Added entry for %d in the cache\n", key);
  logInfo(2,"5. Cached object %v \n", obj );
}

uint32_t NativeStackTrace::cache_size() const {  
  return sizeof(cache) + cache.size()*sizeof_single_cache_entry();
}

uint32_t NativeStackTrace::sizeof_single_cache_entry() const {  
  return sizeof(decltype(cache)::key_type) + sizeof(decltype(cache)::mapped_type);
}

// // To evict an element older than 5 minutes
// int NativeStackTrace::cache_eviction() {
//   LogInfo(2, "DEBUGIZA: Cache eviction - todo \n");
//   this->symbols.push_back(std::string("DEBUGIZA: Cache eviction - todo\n"));
//   return 0;
// }

}  // namespace pyperf
}  // namespace ebpf
