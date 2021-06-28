#include <linux/types.h>
// __wsum is missing from types.h, see
// https://elixir.bootlin.com/linux/v5.13/source/include/uapi/linux/types.h
typedef __u32 __bitwise __wsum;

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <sys/socket.h>
// needed for TC_ACT_*
#include <linux/pkt_cls.h>
#include "bpf_helpers.h"