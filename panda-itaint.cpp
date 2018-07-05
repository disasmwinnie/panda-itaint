/**
 *
 * Authors:
 * Sergej Schmidt          sergejNOSPAMmsgpeek.net
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the LICENSE file in the top-level directory.
 */

#include "panda-itaint.h"

void
ERR(std::string msg) {
    std::cerr << "[ITAINT](ERR): " << msg << std:: endl;
}

void
NFO(std::string msg) {
    std::cout << "[ITAINT](NFO): " << msg << std:: endl;
}

bool
init_plugin(void *self) {
  std::cout << "--]] panda-itaint plugin loaded [[--" << std::endl;
  process_cmd();
  if( action == INVALID )
  {
    ERR("Invalid cmd line arguments");
    return false;
  }

  panda_require("osi");
  assert(init_osi_api());

  panda_require("osi_linux");
  assert(init_osi_linux_api());

  if( panda_os_familyno != OS_LINUX )
  {
    ERR("panda-itaint only supports GNU/Linux guests.");
    return false;
  }

  panda_cb pcb = { .asid_changed = on_asid_change };
  panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

  if(action == TAINT) {
    panda_require("taint2");
    assert(init_taint2_api());

    panda_cb pcb;
    pcb.before_block_translate = apply_taint;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
  }


  if(action == TAINT || action == PARSE_SYSCALLS) {

    panda_require("syscalls2");
    assert(init_osi_linux_api());

#if defined(TARGET_I386)
    PPP_REG_CB("syscalls2", on_sys_socketcall_return, syscall_socketcall_after);
    PPP_REG_CB("syscalls2", on_sys_preadv_return, syscall_preadv_after);
#elif defined(TARGET_ARM)
    PPP_REG_CB("syscalls2", on_sys_socket_return, syscall_socket_after);
    PPP_REG_CB("syscalls2", on_sys_recv_return, syscall_recv_after);
    PPP_REG_CB("syscalls2", on_sys_recvfrom_return, syscall_recvfrom_after);
    PPP_REG_CB("syscalls2", on_sys_recvmsg_return, syscall_recvmsg_after);
#endif
#if defined(TARGET_I386) || defined(TARGET_ARM)
    PPP_REG_CB("syscalls2", on_sys_open_return, syscall_open_after);
    PPP_REG_CB("syscalls2", on_sys_close_return, syscall_close_after);
    PPP_REG_CB("syscalls2", on_sys_read_return, syscall_read_after);
    PPP_REG_CB("syscalls2", on_sys_pread64_return, syscall_pread_after);
    PPP_REG_CB("syscalls2", on_sys_readv_return, syscall_readv_after);
#endif
  }

  return true;
}

void uninit_plugin(void *self)
{
  if( action == COLLECT_PROCS )
  {
    NFO("EXECUTED PROCS DURING TRACE:");
    for( auto it=proc_names.begin(); it != proc_names.end(); ++it )
    {
      std::cout << *it << ", ";
    }
    std::cout << std::endl;
  }
}

void
process_cmd() {
  panda_arg_list *args = panda_get_args("panda-itaint");
  const char* itaint_action = panda_parse_string_req(args, "action",
          "Choose action for itaint: parse_syscalls, taint, collect_procs");
  const char* proc_name = panda_parse_string_opt(args, "proc_name", NULL,
      "Process name, which should be tracked for tainting");
  const char* taint_target = panda_parse_string_opt(args, "msg_type",
      "network", "Which kind of messages should be parsed, choose either"
      "'file' for read files, or 'network'(default).");
  const char* sc_nums = panda_parse_string_opt(args, "syscall_nrs",
      NULL, "Catched syscalls are incremented. Give predefined, dash separated"
      "list of syscall numbers that should trigger tainting.");

  if(itaint_action == nullptr) {
    ERR("Action parameter required. Use --help for possible values.");
    action = INVALID;
    return;
  }

  if(strncmp(itaint_action, "parse_syscalls", 14) == 0) {
    action = PARSE_SYSCALLS;
  } else if(strncmp(itaint_action, "taint", 5) == 0) {
    action = TAINT;
  } else if(strncmp(itaint_action, "collect_procs", 13) == 0) {
    action = COLLECT_PROCS;
  } else {
    ERR("Action parameter required. Use --help for possible values.");
    action = INVALID;
    return;
  }

  if(strncmp(taint_target, "network", 7) == 0) {
    target_network = true;
  } else if(strncmp(taint_target, "file", 4) == 0) {
    target_file = true;
  } else {
    ERR("Taint target must be 'network', for received messages "
      "or 'file', for read files.");
    action = INVALID;
    return;
  }

  if(action == COLLECT_PROCS && sc_nums) {
    ERR("You can not pass syscall numbers when collecting process names!");
    action = INVALID;
    return;
  }

  if((action == TAINT || action == COLLECT_PROCS) && proc_name != NULL) {
    NFO("proc_name:");
    std::cout << std::string(proc_name) << std::endl;
    desired_proc_name = std::string(proc_name);
  }

  // split the given syscall numbers and populate
  if(sc_nums) {
    //list<string> elements;
    std::string sc_nums_new(sc_nums);
    std::string::size_type c_pos = 0;
    std::string::size_type token_pos = sc_nums_new.find('-');
    while(token_pos != std::string::npos) {
      sc_nums_new.substr(c_pos, token_pos);
      uint32_t sc_num = strtoul(sc_nums_new.substr(c_pos, token_pos).c_str(),
          NULL, 10);
      syscall_nrs.push_back(sc_num);
      c_pos = token_pos + 1;
      token_pos = sc_nums_new.find('-', c_pos);
    }
    // last file descriptor
    uint32_t sc_num = strtoul(sc_nums_new.substr(c_pos, token_pos).c_str(),
        NULL, 10);
    syscall_nrs.push_back(sc_num);
    NFO("Following syscall nrs are tracked:");
    for(auto it: syscall_nrs) {
      std::cout << "\t" << it << std::endl;
    }
  }
}

int
on_asid_change(CPUState *cpu, target_ulong old_pgd, target_ulong new_pgd)
{
  if( action == COLLECT_PROCS ) {
    collect_proc_names(cpu, NULL);
  } else {
    set_current_proc_name(cpu);
  }
  return 0;
}

void
collect_proc_names(CPUState* cpu, TranslationBlock* tb)
{
  OsiProc *cp = get_current_process(cpu);
  if(cp == NULL || cp->name == 0 || cp->offset == 0) {
    //ERR("Failed to get the process name");  // to much noise
    free_osiproc(cp);
    return; // can possibly fail
  }

  std::string pn = std::string(cp->name);

  // Only unique ones
  auto it =  std::find(proc_names.begin(), proc_names.end(), pn);
  if( it == proc_names.end() )
  {
    proc_names.push_back(pn);
  }
}

void
set_current_proc_name(CPUState* cpu) {
  OsiProc *cp = get_current_process(cpu);

  if(cp == NULL || cp->name == 0 || cp->offset == 0) {
    free_osiproc(cp);
    ERR("Could not set process name, taint will possibly fail");
    return;
  }

  current_proc_name = std::string(cp->name);
}

bool
is_desired_proc(CPUState* cpu) {
  if(desired_proc_name.empty()) return true;
  if(desired_proc_name.compare(current_proc_name) == 0) return true;
  return false;
}

bool
is_known_socket(int s_fd) {
  auto it = std::find(socket_fds.begin(), socket_fds.end(), s_fd);
  if(it != socket_fds.end()) {
    return true;
  } else {
    return false;
  }
}

bool
is_known_fd(int fd) {
  auto it = std::find(fds.begin(), fds.end(), fd);
  if(it != fds.end()) {
    return true;
  } else {
    return false;
  }
}

void
cpy_str(CPUState* cpu, target_ulong target_addr, unsigned char* buf) {
  uint8_t i=0;
  for (; i<MAX_FILENAME_LEN; ++i) {
    panda_virtual_memory_read(cpu, target_addr+i, ((uint8_t *)buf)+i, 1);
    if(buf[i] == 0) break;
  }

  if(i >= MAX_FILENAME_LEN-1) {
    buf[MAX_FILENAME_LEN] = 0;
  } else {
    buf[i+1] = 0;
  }
}

void
cpy_mem(CPUState* cpu, target_ulong target_addr, void* buffer, ssize_t l) {
  assert(l > 0);
  panda_virtual_memory_read(cpu, target_addr, (uint8_t *)buffer, l);
}

std::string
msg_payload(CPUState* cpu, uint64_t buf_addr, uint64_t len) {
  unsigned char tmp_buf[len] = {0};
  cpy_mem(cpu, buf_addr, tmp_buf, sizeof(tmp_buf));
  return base64_encode(tmp_buf, len);
}

int
apply_taint(CPUState *cpu, target_ulong pc) {

  if(!should_taint) return 1;

  if(!taint2_enabled()) {
    taint2_enable_taint();
    NFO("Taint enabled!");
  }

  for(auto it=taint_areas.begin(); it != taint_areas.end(); ++it) {
    uint64_t buf_addr = it->first;
    ssize_t count = it->second;
    for (int i=0; i<count; ++i) {
      hwaddr pa = panda_virt_to_phys(cpu, buf_addr+i);
      taint2_label_ram(pa, i);
    }
  }

  taint_areas.clear();
  should_taint = false;
  return 0;
}

void
taint_message(int fd, uint64_t buf_addr, uint64_t buf_size,
    int flags, int count, std::string b64enc_payload) {
     /* handle flags */

  assert(count > 0);
  if(flags != 0) {
    if(is_close_on_exec(flags)) handle_sys_close(fd, 0);

    std::cout << "Network syscall with following flag set: "
      << get_flag_name(flags) << std::endl;
  }
  /* handle flags */

  std::cerr << "\trecv socket: " << fd << std::endl;
  std::cerr << "\tbuf_addr: " << buf_addr << std::endl;
  std::cerr << "\tbuf_size: " << buf_size << std::endl;
  std::cerr << "\tflags: " << flags << std::endl;
  std::cerr << "\tRECV leng: " << count << std::endl;
  std::cerr << "\tBase64 encoded message:" << std::endl << b64enc_payload
    << std::endl;

  // Check if this is the correct syscall nr we want.
  bool correct_nr = false;

  if(syscall_nrs.empty()) {
    correct_nr = true;
  } else {
    auto it = std::find(syscall_nrs.begin(), syscall_nrs.end(), syscall_count);
    if(it != syscall_nrs.end()) {
      correct_nr = true;
    }
  }

  NFO("CURRENT SYSCALL NR:");
  std::cout << syscall_count++ << std::endl;
  if(correct_nr) {
    should_taint = true;
    NFO("Tainting this syscall!");
    std::cout << std::endl << std::endl;
    taint_areas.push_back(std::make_pair(buf_addr, count));
  } else {
    NFO("skipping this syscall.");
    std::cout << std::endl << std::endl;
  }

}

void
handle_sys_socket(int s_fd) {
  if(s_fd < 0) {
    ERR("Socket return -1. No fd opened.");
  } else {
    socket_fds.push_back(s_fd);
    NFO("Socket fd OPENED:");
    std::cout << s_fd << std::endl;
  }
}

void
handle_sys_open(int fd, unsigned char* file_name, int flags) {
  if(fd < 0) {
    ERR("open returned -1. No fd opened.");
    // Ensure file is read.
  } else if((flags & O_RDONLY) == O_RDONLY || (flags & O_RDWR) == O_RDWR) {
    socket_fds.push_back(fd);
    NFO("File descriptor OPENED:");
    std::cout << fd << std::endl;
  } else {
    NFO("WARN: unrecognized flags for open()-syscall: ");
    std::cout << flags << std::endl;
  }

  NFO("\tCorresponding file_name is:");
  std::cout << file_name << std::endl;
  NFO("\tCorresponding flags-var is:");
  std::cout << flags << std::endl;
}

void
handle_sys_close(int fd, int status) {
  if(status < 0) {
    ERR("Closing socket or file descriptor FAILED!");
    return;
  }
  auto it = std::find(socket_fds.begin(), socket_fds.end(), fd);

  if(it != socket_fds.end()) {
    socket_fds.erase(it);
    NFO("Socket CLOSED:");
    std::cout << *it << std::endl;
  }
  auto it2 = std::find(fds.begin(), fds.end(), fd);

  if(it2 != fds.end()) {
    fds.erase(it2);
    NFO("File descriptor CLOSED:");
    std::cout << *it2 << std::endl;
  }
}

#if defined(TARGET_I386) || defined(TARGET_ARM)
void
syscall_open_after(CPUState* cpu, target_ulong pc, uint32_t filename,
    int32_t flags, int32_t mode) {

  if(!is_desired_proc(cpu)) return;

  if(!target_file) return;

  CPUArchState *env = (CPUArchState*)cpu->env_ptr;

  NFO("open() encountered.");
  unsigned char str_buf[MAX_FILENAME_LEN] = {0};
  cpy_str(cpu, filename, str_buf);

  handle_sys_open(env->regs[RET_REG], str_buf, flags);
}

void
syscall_close_after(CPUState* cpu, target_ulong pc, uint32_t fd) {

  if(!is_desired_proc(cpu)) return;

  CPUArchState *env = (CPUArchState*)cpu->env_ptr;

  if( (is_known_socket(fd) || is_known_fd(fd)) ) {
    NFO("close() encountered.");
  }
  handle_sys_close(fd, env->regs[RET_REG]);
}

void
syscall_read_after(CPUState* cpu, target_ulong pc, uint32_t fd,
    uint32_t buf_addr, uint32_t buf_size) {

  if(!is_desired_proc(cpu)) return;

  if( !(is_known_socket(fd) || is_known_fd(fd)) ) return;

  CPUArchState *env = (CPUArchState*)cpu->env_ptr;
  NFO("read() encountered.");
  uint64_t ret = env->regs[RET_REG];  // ret of read() is of type int
  if(ret == 0 || ((int) ret) < 0)  {
    ERR("The read()-syscall returned -1 or 0.");
    return;
  }
  NFO("RET:");
  std::cout << ret << std::endl;
  std::string b64enc_payload = msg_payload(cpu, buf_addr, ret);
  // read() on socket fd is the same as recv but with flags=0
  taint_message(fd, buf_addr, buf_size, 0, ret, b64enc_payload);
}

void
syscall_pread_after(CPUState* cpu, target_ulong pc, uint32_t fd,
    uint32_t buf_addr, uint32_t buf_size, uint64_t offset) {

  if(!is_desired_proc(cpu)) return;

  if( !(is_known_socket(fd) || is_known_fd(fd)) ) return;
  CPUArchState *env = (CPUArchState*)cpu->env_ptr;
  NFO("pread() encountered.");
  std::cout << std::endl;
  uint64_t ret = env->regs[RET_REG];  // ret of pread() is of type ssize_t
  if(ret == 0 || ((ssize_t) ret) < 0) {
    ERR("The pread()-syscall returned -1 or 0.");
    return;
  }
  std::string b64enc_payload = msg_payload(cpu, buf_addr+offset, ret);
  // pread() on socket fd is the same as read+offset aka recv but with flags=0
  taint_message(fd, buf_addr+offset, buf_size, 0, ret, b64enc_payload);
}

void
syscall_readv_after(CPUState* cpu, target_ulong pc, uint32_t fd,
    uint32_t iov, uint32_t iovcnt) {

  if(!is_desired_proc(cpu)) return;

  NFO("readv() encountered.");
  handle_pv_read(cpu, pc, fd, iov, iovcnt, 0);
}

void
handle_pv_read(CPUState* cpu, target_ulong pc, uint32_t fd,
    uint32_t iov, uint32_t iovcnt, uint64_t offset) {

  if( !(is_known_socket(fd) || is_known_fd(fd)) ) return;
  CPUArchState *env = (CPUArchState*)cpu->env_ptr;

  // Amount of bytes received.
  uint64_t count = env->regs[RET_REG];
  if(count == ((uint64_t) -1) || count == 0) {
    ERR("The readv()- or preadv()-syscall return -1 or 0.");
    return;
  }
  NFO("recvmsg() overall byte count: ");
  std::cout << count << std::endl;
  my_iovec iovec_arr[iovcnt] = {0};
  cpy_mem(cpu, iov, iovec_arr, sizeof(iovec_arr));
  uint64_t iov_count = 0;

  for(int i=0; i<iovcnt; ++i) {
    // Calc count of bytes.
    // If count is bigger then overall byte count, then buffer is filled out.
    if(count > iovec_arr[i].iov_len) {
      iov_count = iovec_arr[i].iov_len;
      count -= iovec_arr[i].iov_len;
    } else {
      iov_count = count;  // Whats left of count for the last buffer.
    }
    std::string b64enc_payload = msg_payload(cpu, iovec_arr[i].iov_base+offset,
        iov_count);
    taint_message(fd, iovec_arr[i].iov_base+offset, iovec_arr[i].iov_len,
        0, iov_count, b64enc_payload);
    std::cerr << "\treadv-iovec nr: " << i << ", with addr: "
      << iovec_arr[i].iov_base+offset << ", buf_len: " << iovec_arr[i].iov_len
      << ", count: " << iov_count << std::endl;
  } // fori
}
#endif  // if defined(TARGET_I386) || defined(TARGET_ARM)

#if defined(TARGET_I386)
void
syscall_socketcall_after(CPUState* cpu, target_ulong pc, int32_t call_nr,
    uint32_t arg_ptr) {

  if(!is_desired_proc(cpu)) return;

  if(!target_network) return;

  NFO("socketcall entered desired proc.");
  CPUArchState *env = (CPUArchState*)cpu->env_ptr;
  int ret_val = (int) env->regs[RET_REG];

  if(call_nr == SYS_SOCKET) {
    NFO("socketcall: is a socket-call.");
    handle_sys_socket(ret_val); // does validation of ret_val inside method
    return;
  }

  if(call_nr == SYS_RECV || call_nr == SYS_RECVFROM) {

    NFO("recv(from) encountered.");
    if(ret_val <= 0) {
      NFO("The recvmsg()-syscall returned -1 or 0.");
      return;
    }

    int s_fd;
    cpy_mem(cpu, arg_ptr, &s_fd, INT_SIZE);
    // We use this only as a warning. The check for the socket, unlike for the
    // read() call, is purely informational. There should be a warning, though,
    // if network syscall is executed on a socket we didn't catch.
    if(!is_known_socket(s_fd)) {
      std::cout << "WARN: Unknown socket for recv(from): " << s_fd << std::endl;
    }

    uint64_t buf_addr = 0;
    cpy_mem(cpu, arg_ptr+PTR_SIZE, &buf_addr, INT_SIZE);
    uint64_t buf_size = 0;
    // We assume its 32bit long, since we are on ARM and x86
    cpy_mem(cpu, arg_ptr+(PTR_SIZE*2), &buf_size, INT_SIZE);
    int flags = 0;
    // We assume its 32bit long, since we are on ARM and x86
    cpy_mem(cpu, arg_ptr+(PTR_SIZE*3), &flags, INT_SIZE);

    std::string b64enc_payload = msg_payload(cpu, buf_addr, ret_val);
    taint_message(s_fd, buf_addr, buf_size, flags, ret_val, b64enc_payload);
  } else if(call_nr == SYS_RECVMSG) {

    NFO("recvmsg() encountered.");

    if(ret_val <= 0) {
      ERR("The recvmsg()-syscall return -1 or 0.");
      return;
    }

    // Amount of bytes received.
    NFO("recvmsg overall byte count:");
    std::cout << ret_val << std::endl;

    int s_fd;
    cpy_mem(cpu, arg_ptr, &s_fd, sizeof(int));  // First arg
    // We use this only as a warning. The check for the socket, unlike for the
    // read() call, is purely informational. There should be a warning, though,
    // if network syscall is executed on a socket we didn't catch.
    if(!is_known_socket(s_fd)) {
      std::cout << "WARN: Unknown socket for recvmsg: " << s_fd << std::endl;
    }

    // First, get the pointer to the struct. We assume 4 bytes pointer size.
    target_ulong ptr2msghdr_arg;
    cpy_mem(cpu, arg_ptr+PTR_SIZE, &ptr2msghdr_arg, PTR_SIZE); // Second arg

    int flags = 0;
    cpy_mem(cpu, arg_ptr+(PTR_SIZE*2), &flags, INT_SIZE); // Third arg

    // Copy the actual struct.
    struct my_msghdr msghdr_arg = {0};
    cpy_mem(cpu, ptr2msghdr_arg, &msghdr_arg, sizeof(struct my_msghdr));

    // Now we have msg_iovlen and msg_iov, which we can read to reach all the
    // buffers with the actual packet.
    uint64_t iov_arr_len = msghdr_arg.msg_iovlen;  // Amount of buffers

    my_iovec iovec_arr[iov_arr_len] = {0};
    cpy_mem(cpu, msghdr_arg.msg_iov, iovec_arr, sizeof(iovec_arr));
    uint64_t iov_count = 0;
    for(int i=0; i<iov_arr_len; ++i) {
      // Calc count of bytes.
      // If count is bigger then overall byte count, then buffer is filled out.
      if(ret_val > iovec_arr[i].iov_len) {
        iov_count = iovec_arr[i].iov_len;
        ret_val -= iovec_arr[i].iov_len;
      } else {
        iov_count = ret_val;  // Whats left of count for the last buffer.
      }
      std::string b64enc_payload = msg_payload(cpu, iovec_arr[i].iov_base,
          iov_count);
      taint_message(s_fd, iovec_arr[i].iov_base, iovec_arr[i].iov_len,
          flags, iov_count, b64enc_payload);

      std::cerr << "\tiovec nr: " << i << ", with addr: "
        << iovec_arr[i].iov_base << ", buf_len: " << iovec_arr[i].iov_len
        << ", count: " << iov_count << std::endl;
    }

  }
}

void
syscall_preadv_after(CPUState* cpu, target_ulong pc, uint32_t fd,
    uint32_t iov, uint32_t iovcnt, uint32_t pos_l, uint32_t pos_h) {

  if(!is_desired_proc(cpu)) return;

  NFO("preadv() encountered.");
  /* The function call is called with offset, but the syscall splits it into
   * low and high position as arguments. Maybe for compat reasons.
   * In the linux kernel, the offset position is calculated with this function:
   * From commit: 0cc7033aa413527973b92eb1a6bedda8e92da470
   * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/read_write.c#n1023
   *
   * static inline loff_t pos_from_hilo(unsigned long high, unsigned long low)
   * {
   * #define HALF_LONG_BITS (BITS_PER_LONG / 2)
   *  return (((loff_t)high << HALF_LONG_BITS) << HALF_LONG_BITS) | low;
   *  }
   */
  uint64_t offset = (((uint64_t)pos_h << MY_HALF_LONG_BITS) <<
      MY_HALF_LONG_BITS) | pos_l;

  handle_pv_read(cpu, pc, fd, iov, iovcnt, offset);
}
#elif defined(TARGET_ARM)
void
syscall_socket_after(CPUState* cpu, target_ulong pc, int32_t domain,
    int32_t type, int32_t protocol) {

  if(!is_desired_proc(cpu)) return;

  NFO("socket() encountered.");
  CPUArchState *env = (CPUArchState*)cpu->env_ptr;
  uint64_t ret = env->regs[RET_REG];
  handle_sys_socket((int)ret);
}

void
syscall_recv_after(CPUState* cpu, target_ulong pc, int32_t s_fd,
    uint32_t buf_addr, uint32_t buf_size, uint32_t flags) {

  if(!is_desired_proc(cpu)) return;

  if(!target_network) return;

  NFO("recv() encountered.");
  CPUArchState *env = (CPUArchState*)cpu->env_ptr;
  uint64_t ret = env->regs[RET_REG];
  if(((ssize_t)ret) < 0  || ret == 0) {  // ret of recv*() is of type ssize_t
    ERR("The recv()-syscall return -1 or 0.");
    return;
  }
  std::string b64enc_payload = msg_payload(cpu, buf_addr, ret);
  taint_message(s_fd, buf_addr, buf_size, flags, ret, b64enc_payload);
}

void
syscall_recvfrom_after(CPUState* cpu, target_ulong pc, int32_t s_fd,
    uint32_t buf_addr, uint32_t buf_size, uint32_t flags, uint32_t sock_addr,
    uint32_t addrlen) {

  if(!is_desired_proc(cpu)) return;

  if(!target_network) return;

  NFO("recvfrom() encountered.");
  CPUArchState *env = (CPUArchState*)cpu->env_ptr;
  uint64_t ret = env->regs[RET_REG];
  if(((ssize_t)ret) < 0  || ret == 0) {  // ret of recv*() is of type ssize_t
    ERR("The recvfrom()-syscall return -1 or 0.");
    return;
  }
  std::string b64enc_payload = msg_payload(cpu, buf_addr, ret);
  taint_message(s_fd, buf_addr, buf_size, flags, ret, b64enc_payload);
}

void
syscall_recvmsg_after(CPUState* cpu, target_ulong pc, int32_t s_fd,
    uint32_t msg, uint32_t flags) {

  if(!is_desired_proc(cpu)) return;

  if(!target_network) return;

  NFO("recvfrom() encountered.");
  CPUArchState *env = (CPUArchState*)cpu->env_ptr;
  uint64_t count = env->regs[RET_REG];
  if(((ssize_t)count) < 0  || count == 0) {  // ret of recv*() is of type ssize_t
    ERR("The recvmsg()-syscall return -1 or 0.");
    return;
  }
  NFO("recvmsg overall byte count:");
  std::cout << count << std::endl;

  // Copy the actual msghdr struct.
  struct my_msghdr msghdr_arg = {0};
  cpy_mem(cpu, msg, &msghdr_arg, sizeof(struct my_msghdr));

  // Now we have msg_iovlen and msg_iov, which we can read to reach all the
  // buffers with the actual packet.
  uint64_t iov_arr_len = msghdr_arg.msg_iovlen;  // Amount of buffers

  my_iovec iovec_arr[iov_arr_len] = {0};
  cpy_mem(cpu, msghdr_arg.msg_iov, iovec_arr, sizeof(iovec_arr));
  uint64_t iov_count = 0;
  for(int i=0; i<iov_arr_len; ++i) {
    // Calc count of bytes.
    // If count is bigger then overall byte count, then buffer is filled out.
    if(count > iovec_arr[i].iov_len) {
      iov_count = iovec_arr[i].iov_len;
      count -= iovec_arr[i].iov_len;
    } else {
      iov_count = count;  // Whats left of count for the last buffer.
    }
    std::string b64enc_payload = msg_payload(cpu, iovec_arr[i].iov_base,
        iov_count);
    taint_message(s_fd, iovec_arr[i].iov_base, iovec_arr[i].iov_len,
        flags, iov_count, b64enc_payload);

    std::cerr << "\tiovec nr: " << i << ", with addr: "
      << iovec_arr[i].iov_base << ", buf_len: " << iovec_arr[i].iov_len
      << ", count: " << iov_count << std::endl;
  }

}
#endif  // #if defined(TARGET_I386) #elif defined(TARGET_ARM)
