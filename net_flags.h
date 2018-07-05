/**
 *
 * Authors:
 * Sergej Schmidt          sergejNOSPAMmsgpeek.net
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the LICENSE file in the top-level directory.
 */

#ifndef __NET_FLAGS_H_
#define __NET_FLAGS_H_
#include <string>
#include <map>

/*
 * Holds constants with possible values for flags parameters, defined in
 * "sys/socket.h", whiche could used in recv* syscalls.
 */

static std::map<int, std::string> flag_map {
  /* close-on-exit flag, must be handled in Tracer. At this point purely
     informational. */
  { 1073741824, "MSG_CMSG_CLOEXEC" },
    /* Non-blocking. Makes sense to used this with poll or select.
       Purely informational. */
    { 64,         "MSG_DONTWAIT" },
    /* Means there was an error and the buffer contains the packet, that was not
       sent. If this was previously not set, a new packet must begin. As, when
       next recv* that has this flag _not_ set must be a new packet. */
    { 8192,       "MSG_ERRQUEUE" },
    /* Receive out-of-band data. This call is used (or makes sense to use) when
       a SIGURG was received. This basically tells, that "urgent" data should be
       received. If a recv* with this flags arrives, handle it as new packet. */
    { 1,          "MSG_OOB" },
    /* The queue for receiving queue is not incremented. Analogus to
       lseek(fd, 0, SEEK_SET). When this flag is used, handle next recv* as
       contining message. */
    { 2,          "MSG_PEEK" },
    /* Return the real length of datagram, even if it didn't fit into the buffer. */
    { 32,         "MSG_TRUNC" },
    /* Explicitly, purely informational. */
    { 256,        "MSG_WAITALL" }

};

bool
is_close_on_exec(int flags);

std::string
get_flag_name(int flags);
#endif
