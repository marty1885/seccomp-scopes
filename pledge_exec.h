#pragma once
#include <linux/filter.h>  /* struct sock_fprog */

void append_exec_filter(unsigned int scopes, struct sock_fprog* prog);