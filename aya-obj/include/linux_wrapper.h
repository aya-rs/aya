#include <asm-generic/socket.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/if_link.h>
#include <linux/netfilter.h>
#include <linux/perf_event.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>

/* workaround the fact that bindgen can't parse the IOC macros */
int AYA_PERF_EVENT_IOC_ENABLE = PERF_EVENT_IOC_ENABLE;
int AYA_PERF_EVENT_IOC_DISABLE = PERF_EVENT_IOC_DISABLE;
int AYA_PERF_EVENT_IOC_SET_BPF = PERF_EVENT_IOC_SET_BPF;
