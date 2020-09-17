#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
import argparse
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
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 rwflag;
    u32 pid;
    char mode[32];
    char comm[TASK_COMM_LEN];
    char fname[DNAME_INLINE_LEN];
};

BPF_HASH(counts, struct data_t);
BPF_PERF_OUTPUT(events);

int read_trace(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t data = {};

    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;
    int mode = file->f_inode->i_mode;
    if(S_ISDIR(mode))
        strcpy(data.mode,"DIRECTORY");
    else if(S_ISCHR(mode))
        strcpy(data.mode,"CHARACTER SPECIAL");
    else if(S_ISBLK(mode))
        strcpy(data.mode,"BLOCK SPECIAL");
    else if(S_ISREG(mode))
        strcpy(data.mode,"REGULAR");
    else if(S_ISFIFO(mode))
        strcpy(data.mode,"FIFO SPECIAL/PIPE");
    else if(S_ISLNK(mode))
        strcpy(data.mode,"SYMBOLIC LINK");
    else
        strcpy(data.mode, "UNKNOWN");
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        data.pid = pid;
        bpf_probe_read_kernel(&data.fname, sizeof(data.fname), d_name.name);
    }
    data.rwflag = 0;  // read
    counts.increment(data);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
};

int write_trace(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t data = {};

    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;
    int mode = file->f_inode->i_mode;
    if(S_ISDIR(mode))
        strcpy(data.mode,"DIRECTORY");
    else if(S_ISCHR(mode))
        strcpy(data.mode,"CHARACTER SPECIAL");
    else if(S_ISBLK(mode))
        strcpy(data.mode,"BLOCK SPECIAL");
    else if(S_ISREG(mode))
        strcpy(data.mode,"REGULAR");
    else if(S_ISFIFO(mode))
        strcpy(data.mode,"FIFO SPECIAL/PIPE");
    else if(S_ISLNK(mode))
        strcpy(data.mode,"SYMBOLIC LINK");
    else
        strcpy(data.mode, "UNKNOWN");

    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        data.pid = pid;
        bpf_probe_read_kernel(&data.fname, sizeof(data.fname), d_name.name);
    }
    data.rwflag = 1;  // write
    counts.increment(data);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
};
"""

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_read", fn_name="read_trace")
b.attach_kprobe(event="vfs_readv", fn_name="read_trace")
b.attach_kprobe(event="vfs_write", fn_name="write_trace")
b.attach_kprobe(event="vfs_writev", fn_name="write_trace")

print("Tracing... Ctrl-C to end.")

# output
try:
    sleep(interval)
except KeyboardInterrupt:
    pass

prev_pid = -1
# header
print("\n%-8s %-7s %-20s %-20s %-20s %-10s %-8s" % ("TIME", "PID", "COMM", "FILENAME", "TYPE", "READ/WRITE", "COUNT"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[0].pid):
    # print("%-26s %8d" % (k.filename.decode('utf-8', 'replace'), v.pid))
    rw = ""
    if k.rwflag==0:
        rw = "READ"
    else:
        rw = "WRITE"
    if k.pid != prev_pid:
        prev_pid = k.pid
        print("---------------------------------------------------------------------------------------------------------")
    print("%-8s %-7s %-20s %-20s %-20s %-10s %-8s" % (strftime("%H:%M:%S"), k.pid,
        k.comm.decode('utf-8', 'replace'),
        k.fname.decode('utf-8', 'replace'), k.mode.decode('utf-8', 'replace'), rw, v.value))