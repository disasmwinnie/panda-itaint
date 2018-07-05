/**
 *
 * Authors:
 * Sergej Schmidt          sergejNOSPAMmsgpeek.net
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the LICENSE file in the top-level directory.
 */

#include "net_flags.h"

bool
is_close_on_exec(int flags) {
  if(flags == 1073741824) return true;
  return false;
}

std::string
get_flag_name(int flags) {
  std::string flag_name;

  for(auto const &el : flag_map) {
    if((flags & el.first) == el.first) {
      flag_name += " " + el.second;
    }
  }
  if(flag_name.empty()) flag_name = "INVALID_FLAG!?";
  return flag_name;
}

