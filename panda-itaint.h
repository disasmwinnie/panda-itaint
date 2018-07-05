/**
 *
 * Authors:
 * Sergej Schmidt          sergejNOSPAMmsgpeek.net
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the LICENSE file in the top-level directory.
 */

#ifndef PANDA_ITAINT_H__
#define PANDA_ITAINT_H__

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <cassert>
#include <iostream>
#include <utility>
#include <string>
#include <list>
#include <algorithm>


#include "net_flags.h"
#include "base64.h"

#include "taint2/taint2.h"

#include "syscalls2/syscalls2.h"
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "osi_linux/osi_linux_ext.h"

#include "syscalls2/gen_syscalls_ext_typedefs.h"

#include "taint2/taint2_ext.h"

bool
init_plugin(void *);

void
uninit_plugin(void *);
}  // extern "C"

#define MAX_FILENAME_LEN 40

#if defined(TARGET_I386)

#define RET_REG R_EAX

/* First arg of the socket-syscall. GNULinux 32bit (only) */
#define SYS_SOCKET 1
#define SYS_RECV 10
#define SYS_RECVFROM 12
#define SYS_RECVMSG 17
#define SYS_RECVMMSG 19
/* First arg of the socket-syscall. GNULinux 32bit (only) */

#elif defined(TARGET_ARM)

#define RET_REG 0

#endif


void
process_cmd();

int
on_asid_change(CPUState *cpu, target_ulong old_pgd, target_ulong new_pgd);

void
collect_proc_names(CPUState* cpu, TranslationBlock* tb);

void
set_current_proc_name(CPUState* cpu);

enum
Cmd_action { INVALID, PARSE_SYSCALLS, COLLECT_PROCS, TAINT } action;

bool
target_file = false;

bool
target_network = false;

std::string
desired_proc_name = "";

std::string
current_proc_name;

std::list<std::string>
proc_names;

// List with currently opened sockets, aka network file descriptors.
std::list<int>
socket_fds;

// List with currently opened file descriptors.
std::list<int>
fds;

// List of user defined syscall numbers to be tracked. Every relevant syscall
// is given an increment number.
// Taint memory only if it matches the user defined ones.
std::list<int>
syscall_nrs;

// Counter of current syscalls
static uint32_t
syscall_count = 0;

// Contains a list with addr and size to be tainted as soon as it's possible.
// This is usually when an BEFORE_BLOCK_TRANSLATE happens.
std::list<std::pair<uint64_t, ssize_t>>
taint_areas;

// Set to true on the first occurance of a message. Used to determine whether
// to enable taint2-plugin when a BEFORE_BLOCK_TRANSLATE happnes.
static bool
should_taint = false;

bool
is_desired_proc(CPUState* cpu);

bool
is_known_socket(int s_fd);

bool
is_known_fd(int fd);

void
cpy_str(CPUState* cpu, target_ulong target_addr, unsigned char* buf);

void
cpy_mem(CPUState* cpu, target_ulong target_addr, void* buffer, ssize_t l);

std::string
msg_payload(CPUState* cpu, uint64_t buf_addr, uint64_t len);

int
apply_taint(CPUState *cpu, target_ulong pc);

void
taint_message(int s_fd, uint64_t buf_addr, uint64_t buf_size,
    int flags, int count, std::string b64enc_payload);

void
handle_sys_socket(int s_fd);

void
handle_sys_open(int fd, unsigned char* file_name, int flags);

void
handle_sys_close(int s_fd, int status);

#if defined(TARGET_I386) || defined(TARGET_ARM)
/* Needed to read from memory. This is totally dangerous, since int is
 * guaranteed to be at least 16bit long,. In practice it is 32bit by most
 * implementations. Still, there is other way to state this, except the
 * assumption.
 */
#define PTR_SIZE 4

#define INT_SIZE 4

/* Used in syscall_preadv_after() */
#define MY_BITS_PER_LONG 64 // This is fine for unix, only MS uses 32bit
#define MY_HALF_LONG_BITS (MY_BITS_PER_LONG / 2)

/*
 * Redifinition of structs, used by recvmsg-call. For portability reasons this
 * is copied from the man page instead of including <sys/socket.h>. All size_t
 * variables were changed to uint32_t, since size_t is usually sizeof pointer.
 * This is also true for "socklen_t msg_namelen", which is usually (not always)
 * defined as size_t.
 * When you planning to use this for 64-bit targets, the following variable
 * types have to be adjusted: iov_len, msg_namelen, msg_iovlen, msg_controlen.
 */
struct my_iovec {
  uint32_t  iov_base;  // Original type is "void*"
  uint32_t  iov_len;
};

struct my_msghdr {
  // void* replaced with uint32_t, but needed for the right offset, since host
  // pointer size can be diffrent. Mostly bullshit value we won't read. The
  // msg_iov is interpreted as pointer.
  uint32_t  msg_name;
  uint32_t  msg_namelen;
  uint32_t  msg_iov;  // Original type is "struct my_iovec*"
  uint32_t  msg_iovlen;
  uint32_t  msg_control;  // Original type is "void*"
  uint32_t  msg_controllen;
  int       msg_flags;
};

void
syscall_open_after(CPUState* cpu, target_ulong pc, uint32_t filename,
    int32_t flags, int32_t mode);

void
syscall_close_after(CPUState* cpu, target_ulong pc, uint32_t s_fd);

void
syscall_read_after(CPUState* cpu, target_ulong pc, uint32_t fd,
    uint32_t buf_addr, uint32_t buf_size);

void
syscall_pread_after(CPUState* cpu, target_ulong pc, uint32_t s_fd,
    uint32_t buf_addr, uint32_t buf_size, uint64_t offset);

void
syscall_readv_after(CPUState* cpu, target_ulong pc, uint32_t s_fd,
    uint32_t iov, uint32_t iovcnt);

/*
 * Wrapper for preadv and readv.
 */
void
handle_pv_read(CPUState* cpu, target_ulong pc, uint32_t s_fd,
    uint32_t iov, uint32_t iovcnt, uint64_t offset);
#endif  // if defined(TARGET_I386) || defined(TARGET_ARM)

#if defined(TARGET_I386)
void
syscall_socketcall_after(CPUState* cpu, target_ulong pc, int32_t call_nr,
    uint32_t arg_ptr);

void
syscall_preadv_after(CPUState* cpu, target_ulong pc, uint32_t s_fd,
    uint32_t iov, uint32_t iovcnt, uint32_t pos_l, uint32_t pos_h);
#elif defined(TARGET_ARM)
void
syscall_socket_after(CPUState* cpu, target_ulong pc, int32_t domain,
    int32_t type, int32_t protocol);

void
syscall_recv_after(CPUState* cpu, target_ulong pc, int32_t s_fd,
    uint32_t buf_addr, uint32_t buf_size, uint32_t flags);

void
syscall_recvfrom_after(CPUState* cpu, target_ulong pc, int32_t s_fd,
    uint32_t buf_addr, uint32_t buf_size, uint32_t flags, uint32_t sock_addr,
    uint32_t addrlen);

void
syscall_recvmsg_after(CPUState* cpu, target_ulong pc, int32_t s_fd,
    uint32_t msg, uint32_t flags);
#endif  // #if defined(TARGET_I386) #elif defined(TARGET_ARM)

#endif  // define __PANDA-ITAINT__

