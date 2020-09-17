#!/usr/bin/python
from bcc import BPF
from time import strftime, sleep
from sys import argv


interval = 99999999
if len(argv) > 1:
    try:
        interval = int(argv[1])
        if interval == 0:
            raise
    except:  # also catches -h, --help
        pass

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>

struct key_t {
    char filename[TASK_COMM_LEN];
};

BPF_HASH(counts, struct key_t, u64, 256);

int do_count(struct pt_regs *ctx, struct vm_area_struct *vma) {
    struct key_t key = {};
    struct file *f = vma->vm_file;
    struct dentry *de = f->f_path.dentry;
    struct qstr d_name = de->d_name;
    bpf_probe_read_kernel(&key.filename, sizeof(key.filename), d_name.name);
    counts.increment(key);
    return 0;
}

"""

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="handle_mm_fault", fn_name="do_count")

# header
print("Tracing... Ctrl-C to end.")

# output
try:
    sleep(interval)
except KeyboardInterrupt:
    pass

print("\n%-26s %8s" % ("FILENAME", "COUNT"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%-26s %8d" % (k.filename.decode('utf-8', 'replace'), v.value))
