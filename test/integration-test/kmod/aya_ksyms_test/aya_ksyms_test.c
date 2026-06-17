#include <linux/init.h>
#include <linux/module.h>
#include <linux/percpu-defs.h>

DEFINE_PER_CPU(int, aya_ksyms_test_var) = 123;
EXPORT_PER_CPU_SYMBOL_GPL(aya_ksyms_test_var);

static int __init aya_ksyms_test_init(void) {
  if (this_cpu_read(aya_ksyms_test_var) != 123)
    return -EINVAL;

  return 0;
}

static void __exit aya_ksyms_test_exit(void) {}

module_init(aya_ksyms_test_init);
module_exit(aya_ksyms_test_exit);

MODULE_LICENSE("GPL");
