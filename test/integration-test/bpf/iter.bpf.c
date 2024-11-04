// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

char _license[] SEC("license") = "GPL";

SEC("iter/task")
int iter_task(struct bpf_iter__task *ctx) {
  struct seq_file *seq = ctx->meta->seq;
  struct task_struct *task = ctx->task;
  // Verifier requires this check.
  if (task == NULL) {
    return 0;
  }

  if (ctx->meta->seq_num == 0) {
    BPF_SEQ_PRINTF(seq, "tgid     pid      name\n");
  }
  BPF_SEQ_PRINTF(seq, "%-8d %-8d %s\n", task->tgid, task->pid, task->comm);

  return 0;
}
