#pragma once
#include <linux/filter.h>  /* struct sock_fprog */

void append_proc_filter(unsigned int scopes, struct sock_fprog* prog);