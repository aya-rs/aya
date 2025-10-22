#include <linux/types.h>
// __wsum is missing from types.h, compare:
// https://github.com/torvalds/linux/blob/v5.13/include/uapi/linux/types.h
// https://github.com/libbpf/libbpf/blob/v1.5.0/include/linux/types.h
typedef __u32 __bitwise __wsum;

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/bpf_perf_event.h>
// needed for TC_ACT_*
#include <linux/pkt_cls.h>
#include <linux/ptrace.h>
#include <sys/socket.h>
